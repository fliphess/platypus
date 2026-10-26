package bootstrap

import (
	"context"
	"net/url"
	"testing"
	"time"

	"platypus/internal/seal"

	"go.uber.org/zap"

	"platypus/internal/access"
	"platypus/internal/audit"
	"platypus/internal/config"
	"platypus/internal/database/dbtest"
	"platypus/internal/db"
	"platypus/internal/lockout"
	"platypus/internal/mfa"
	"platypus/internal/sensitive"
	"platypus/internal/store/memstore"
)

const tokenParam = "/platypus/bootstrap-token"

type fixture struct {
	svc    *Service
	mfa    *mfa.Service
	users  *access.Service
	params *memstore.Parameters
	q      *db.Queries
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pool := dbtest.New(t)
	q := db.New(pool)
	recorder := audit.NewRecorder(q, zap.NewNop())
	guard := lockout.NewGuard(q, recorder)
	sealer, _ := seal.New(sensitive.New(config.TestEncryptionKey))
	publicURL, _ := url.Parse("https://platypus.example.com")
	mfaService, err := mfa.NewService(pool, sealer, publicURL, guard, recorder)
	if err != nil {
		t.Fatal(err)
	}
	params := memstore.NewParameters()
	svc := NewService(pool, params, mfaService, guard, recorder, Config{TokenParam: tokenParam, TokenTTL: time.Hour})
	return fixture{svc: svc, mfa: mfaService, users: access.NewService(pool, recorder, []string{"example.com"}), params: params, q: q}
}

func (f fixture) tokenFromSSM(t *testing.T) string {
	t.Helper()
	value, err := f.params.Value(context.Background(), tokenParam, 0)
	if err != nil {
		t.Fatalf("read token from SSM: %v", err)
	}
	return value.Reveal()
}

func TestFullBootstrap(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	issued, err := f.svc.EnsureToken(ctx)
	if err != nil || !issued {
		t.Fatalf("EnsureToken = %v, %v", issued, err)
	}
	if issued, _ := f.svc.EnsureToken(ctx); issued {
		t.Error("a second token was issued while the first is valid")
	}

	user, _ := f.users.UserForLogin(ctx, "first@example.com", "", nil)
	if _, err := f.svc.VerifyToken(ctx, user, "wrong"); err == nil {
		t.Fatal("a wrong token was accepted")
	}
	tokenID, err := f.svc.VerifyToken(ctx, user, f.tokenFromSSM(t))
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}

	// Completing needs a second factor and recovery codes.
	if err := f.svc.Complete(ctx, user, tokenID); err == nil {
		t.Fatal("bootstrap completed without a second factor")
	}
	enrollment, _ := f.mfa.StartTOTPEnrollment(ctx, user)
	confirmTOTP(t, f.mfa, user, enrollment.Secret)
	if err := f.svc.Complete(ctx, user, tokenID); err == nil {
		t.Fatal("bootstrap completed without recovery codes")
	}
	if _, err := f.mfa.IssueRecoveryCodes(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Complete(ctx, user, tokenID); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	state, _ := f.q.GetAppState(ctx)
	admin, _ := f.q.GetUser(ctx, user.ID)
	policies, _ := f.q.ListPolicies(ctx, "%")
	if !state.Bootstrapped || !admin.IsAdmin || len(policies) != len(access.DefaultPolicies) {
		t.Fatalf("after bootstrap: state=%+v admin=%v policies=%d", state, admin.IsAdmin, len(policies))
	}

	// The token is used up.
	other, _ := f.users.UserForLogin(ctx, "second@example.com", "", nil)
	if err := f.svc.Complete(ctx, other, tokenID); err == nil {
		t.Error("a used token completed a second bootstrap")
	}
	if issued, _ := f.svc.EnsureToken(ctx); issued {
		t.Error("a token was issued after bootstrap")
	}
}

func TestResetKeepsDataAndIssuesNewToken(t *testing.T) {
	f := newFixture(t)
	ctx := audit.WithActor(context.Background(), audit.ActorCLI)
	if err := f.q.SetBootstrapped(ctx, true); err != nil {
		t.Fatal(err)
	}
	user, _ := f.users.UserForLogin(ctx, "keeps@example.com", "", nil)

	if err := f.svc.Reset(ctx); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	state, _ := f.q.GetAppState(ctx)
	if state.Bootstrapped {
		t.Error("reset didn't switch back to bootstrap mode")
	}
	if _, err := f.q.GetUser(ctx, user.ID); err != nil {
		t.Error("reset removed a user")
	}
	if _, err := f.svc.VerifyToken(ctx, user, f.tokenFromSSM(t)); err != nil {
		t.Errorf("new token doesn't work: %v", err)
	}
}

func TestVerifyTokenRemovesOldFactors(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user, _ := f.users.UserForLogin(ctx, "old@example.com", "", nil)
	if _, err := f.mfa.IssueRecoveryCodes(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.EnsureToken(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.VerifyToken(ctx, user, f.tokenFromSSM(t)); err != nil {
		t.Fatal(err)
	}
	if factors, _ := f.mfa.Factors(ctx, user.ID); factors.RecoveryCodesLeft != 0 {
		t.Error("old recovery codes survived the bootstrap token")
	}
}
