// Package bootstrap sets platypus up the first time, and again after a reset.
//
// Until bootstrap completes, platypus does nothing else. The worker writes a
// one-time token to an SSM parameter; only people with access to SSM in the
// AWS account can read it. The first user to enter it, set up a second factor
// and save recovery codes joins the admin group.
package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"platypus/internal/access"
	"platypus/internal/audit"
	"platypus/internal/database"
	"platypus/internal/db"
	"platypus/internal/lockout"
	"platypus/internal/mfa"
	"platypus/internal/problem"
	"platypus/internal/secrethash"
	"platypus/internal/sensitive"
	"platypus/internal/store"
)

// Service runs the bootstrap.
type Service struct {
	pool       *pgxpool.Pool
	queries    *db.Queries
	parameters store.TokenWriter
	mfa        *mfa.Service
	guard      *lockout.Guard
	audit      *audit.Recorder
	tokenParam string
	tokenTTL   time.Duration
	now        func() time.Time
}

// Config holds the bootstrap settings.
type Config struct {
	// TokenParam is the SSM parameter the token is written to.
	TokenParam string
	// TokenTTL is how long a token stays valid.
	TokenTTL time.Duration
}

// NewService returns a Service.
func NewService(pool *pgxpool.Pool, parameters store.TokenWriter, mfaService *mfa.Service,
	guard *lockout.Guard, recorder *audit.Recorder, cfg Config) *Service {
	return &Service{
		pool:       pool,
		queries:    db.New(pool),
		parameters: parameters,
		mfa:        mfaService,
		guard:      guard,
		audit:      recorder,
		tokenParam: cfg.TokenParam,
		tokenTTL:   cfg.TokenTTL,
		now:        time.Now,
	}
}

// EnsureToken issues a token when platypus isn't bootstrapped and no valid
// token exists. The worker calls it regularly. It reports whether it issued one.
func (s *Service) EnsureToken(ctx context.Context) (bool, error) {
	state, err := s.queries.GetAppState(ctx)
	if err != nil {
		return false, fmt.Errorf("load app state: %w", err)
	}
	if state.Bootstrapped {
		return false, nil
	}
	valid, err := s.queries.ListValidBootstrapTokens(ctx)
	if err != nil {
		return false, fmt.Errorf("list bootstrap tokens: %w", err)
	}
	if len(valid) > 0 {
		return false, nil
	}
	return true, s.issue(ctx, audit.ActorWorker.Email)
}

// Reset puts platypus back into bootstrap mode and issues a new token. All
// data stays; whoever completes the bootstrap joins the admin group.
func (s *Service) Reset(ctx context.Context) error {
	err := database.InTx(ctx, s.pool, func(q *db.Queries) error {
		if err := q.RevokeBootstrapTokens(ctx); err != nil {
			return err
		}
		if err := q.EndAllAdminModes(ctx); err != nil {
			return err
		}
		return q.SetBootstrapped(ctx, false)
	})
	if err != nil {
		return fmt.Errorf("reset bootstrap: %w", err)
	}
	if err := s.audit.Record(ctx, audit.Event{Action: audit.ActionBootstrapReset, Outcome: audit.Allowed}); err != nil {
		return err
	}
	return s.issue(ctx, audit.ActorFrom(ctx).Email)
}

// issue writes a new token to SSM first and records its hash after, so a
// failed SSM write never leaves a valid token nobody can read.
func (s *Service) issue(ctx context.Context, issuedBy string) error {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("generate bootstrap token: %w", err)
	}
	token := sensitive.New(base64.RawURLEncoding.EncodeToString(raw))

	hash, err := secrethash.Hash(token.Reveal())
	if err != nil {
		return err
	}
	expires := s.now().Add(s.tokenTTL)
	description := fmt.Sprintf("Platypus bootstrap token, valid until %s", expires.UTC().Format(time.RFC3339))
	if err := s.parameters.Write(ctx, s.tokenParam, token, description); err != nil {
		return fmt.Errorf("write bootstrap token to %s: %w", s.tokenParam, err)
	}

	_, err = s.queries.CreateBootstrapToken(ctx, db.CreateBootstrapTokenParams{
		TokenHash: hash, IssuedBy: issuedBy, ExpiresAt: expires,
	})
	if err != nil {
		return fmt.Errorf("store bootstrap token: %w", err)
	}
	return s.audit.Record(ctx, audit.Event{Action: audit.ActionBootstrapTokenIssued, Outcome: audit.Allowed,
		Name: s.tokenParam, Kind: "ssm", Details: map[string]any{"expires_at": expires}})
}

// VerifyToken checks a token entered by user. On success the user's old
// second factors are removed: they start over with fresh ones. Failures count
// towards the lockout.
func (s *Service) VerifyToken(ctx context.Context, user db.User, token string) (int64, error) {
	candidates, err := s.queries.ListValidBootstrapTokens(ctx)
	if err != nil {
		return 0, fmt.Errorf("list bootstrap tokens: %w", err)
	}
	for _, candidate := range candidates {
		if !secrethash.Verify(token, candidate.TokenHash) {
			continue
		}
		if err := s.mfa.RemoveAll(ctx, user.ID); err != nil {
			return 0, fmt.Errorf("remove old factors: %w", err)
		}
		if err := s.guard.Succeeded(ctx, user.ID); err != nil {
			return 0, err
		}
		s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionBootstrapTokenEntered, Outcome: audit.Allowed})
		return candidate.ID, nil
	}
	return 0, s.guard.Failed(ctx, user.ID, "bootstrap token")
}

// TokenStillValid reports whether a verified token can still complete the
// bootstrap (not used, revoked or expired since).
func (s *Service) TokenStillValid(ctx context.Context, tokenID int64) (bool, error) {
	return s.queries.IsBootstrapTokenValid(ctx, tokenID)
}

// Complete finishes the bootstrap: user joins the admin group, the token is
// used up and the default policies are created the first time.
func (s *Service) Complete(ctx context.Context, user db.User, tokenID int64) error {
	factors, err := s.mfa.Factors(ctx, user.ID)
	if err != nil {
		return err
	}
	if !factors.Any() {
		return problem.Invalid("Set up an authenticator app or a passkey first.")
	}
	if factors.RecoveryCodesLeft == 0 {
		return problem.Invalid("Create your recovery codes first.")
	}

	var seeded bool
	err = database.InTx(ctx, s.pool, func(q *db.Queries) error {
		if _, err := q.UseBootstrapToken(ctx, db.UseBootstrapTokenParams{ID: tokenID, UsedBy: &user.ID}); err != nil {
			if database.IsNoRows(err) {
				return problem.Conflict("This bootstrap token is no longer valid; ask for a new one.")
			}
			return err
		}
		if err := q.SetUserAdmin(ctx, db.SetUserAdminParams{ID: user.ID, IsAdmin: true}); err != nil {
			return err
		}
		if seeded, err = access.SeedDefaultPolicies(ctx, q); err != nil {
			return err
		}
		return q.SetBootstrapped(ctx, true)
	})
	if err != nil {
		return err
	}

	if seeded {
		s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionPoliciesSeed, Outcome: audit.Allowed})
	}
	return s.audit.Record(ctx, audit.Event{Action: audit.ActionBootstrapCompleted, Outcome: audit.Allowed,
		Details: map[string]any{"admin": user.Email}})
}
