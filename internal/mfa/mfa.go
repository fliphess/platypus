// Package mfa manages the second factors that guard admin mode: TOTP codes,
// passkeys (WebAuthn) and one-time recovery codes.
//
// Failed attempts count towards a lockout (package lockout). Enrolling a
// factor doesn't: a typo while setting up shouldn't lock anyone out.
package mfa

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"platypus/internal/seal"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"

	"platypus/internal/audit"
	"platypus/internal/database"
	"platypus/internal/db"
	"platypus/internal/lockout"
)

// Service manages second factors.
type Service struct {
	pool     *pgxpool.Pool
	queries  *db.Queries
	sealer   *seal.Sealer
	webauthn *webauthn.WebAuthn
	guard    *lockout.Guard
	audit    *audit.Recorder
	now      func() time.Time
}

// NewService returns a Service. passkeyOrigin is where users open platypus:
// the passkey origin, and its host the relying party ID. Without it passkeys
// are off.
func NewService(pool *pgxpool.Pool, sealer *seal.Sealer, passkeyOrigin *url.URL, guard *lockout.Guard, recorder *audit.Recorder) (*Service, error) {
	var wa *webauthn.WebAuthn
	if passkeyOrigin != nil {
		var err error
		wa, err = webauthn.New(&webauthn.Config{
			RPID:          passkeyOrigin.Hostname(),
			RPDisplayName: "Platypus",
			RPOrigins:     []string{passkeyOrigin.Scheme + "://" + passkeyOrigin.Host},
		})
		if err != nil {
			return nil, fmt.Errorf("configure passkeys: %w", err)
		}
	}
	return &Service{
		pool:     pool,
		queries:  db.New(pool),
		sealer:   sealer,
		webauthn: wa,
		guard:    guard,
		audit:    recorder,
		now:      time.Now,
	}, nil
}

// Factors is what a user has enrolled.
type Factors struct {
	TOTP              bool
	Passkeys          []db.Passkey
	RecoveryCodesLeft int
}

// Any reports whether the user can confirm admin mode at all.
func (f Factors) Any() bool {
	return f.TOTP || len(f.Passkeys) > 0
}

// AnyIncludingRecoveryCodes reports whether the user has anything that can
// confirm admin mode, recovery codes included.
func (f Factors) AnyIncludingRecoveryCodes() bool {
	return f.Any() || f.RecoveryCodesLeft > 0
}

// Factors returns the enrolled factors of a user.
func (s *Service) Factors(ctx context.Context, userID int64) (Factors, error) {
	var factors Factors

	totp, err := s.queries.GetTOTP(ctx, userID)
	switch {
	case err == nil:
		factors.TOTP = totp.ConfirmedAt != nil
	case !database.IsNoRows(err):
		return Factors{}, fmt.Errorf("load TOTP: %w", err)
	}

	if factors.Passkeys, err = s.queries.ListPasskeys(ctx, userID); err != nil {
		return Factors{}, fmt.Errorf("load passkeys: %w", err)
	}

	codes, err := s.queries.ListUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		return Factors{}, fmt.Errorf("load recovery codes: %w", err)
	}
	factors.RecoveryCodesLeft = len(codes)
	return factors, nil
}

// RemoveAll deletes every factor of a user. Bootstrap uses it: whoever
// proves access to the bootstrap token starts over with fresh factors.
func (s *Service) RemoveAll(ctx context.Context, userID int64) error {
	return database.InTx(ctx, s.pool, func(q *db.Queries) error {
		if err := q.DeleteTOTP(ctx, userID); err != nil {
			return err
		}
		if err := q.DeleteAllPasskeys(ctx, userID); err != nil {
			return err
		}
		return q.DeleteRecoveryCodes(ctx, userID)
	})
}

// userContext binds sealed values to their owner.
func userContext(userID int64) []byte {
	return []byte("user:" + strconv.FormatInt(userID, 10))
}
