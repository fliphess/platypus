package mfa

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"platypus/internal/seal"

	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"platypus/internal/access"
	"platypus/internal/audit"
	"platypus/internal/config"
	"platypus/internal/database/dbtest"
	"platypus/internal/db"
	"platypus/internal/lockout"
	"platypus/internal/problem"
	"platypus/internal/sensitive"
)

type fixture struct {
	svc   *Service
	user  db.User
	clock *time.Time
	q     *db.Queries
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pool := dbtest.New(t)
	q := db.New(pool)
	recorder := audit.NewRecorder(q, zap.NewNop())
	sealer, _ := seal.New(sensitive.New(config.TestEncryptionKey))
	publicURL, _ := url.Parse("https://platypus.example.com")

	svc, err := NewService(pool, sealer, publicURL, lockout.NewGuard(q, recorder), recorder)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	clock := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return clock }

	users := access.NewService(pool, recorder, []string{"example.com"})
	user, err := users.UserForLogin(context.Background(), "admin@example.com", "", nil)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return fixture{svc: svc, user: user, clock: &clock, q: q}
}

func TestTOTPEnrollAndVerify(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	enrollment, err := f.svc.StartTOTPEnrollment(ctx, f.user)
	if err != nil {
		t.Fatalf("StartTOTPEnrollment: %v", err)
	}
	if !strings.HasPrefix(enrollment.QRCode, "data:image/png;base64,") {
		t.Error("QR code should be a PNG data URI")
	}
	code := func() string {
		c, _ := totp.GenerateCode(enrollment.Secret, *f.clock)
		return c
	}

	// A pending secret doesn't count as a factor and can't open admin mode.
	if factors, _ := f.svc.Factors(ctx, f.user.ID); factors.TOTP {
		t.Error("unconfirmed TOTP counted as a factor")
	}
	if err := f.svc.VerifyTOTP(ctx, f.user.ID, code()); err == nil {
		t.Error("unconfirmed TOTP opened admin mode")
	}

	if err := f.svc.ConfirmTOTPEnrollment(ctx, f.user, "000000"); err == nil {
		t.Error("a wrong code confirmed the enrollment")
	}
	if err := f.svc.ConfirmTOTPEnrollment(ctx, f.user, code()); err != nil {
		t.Fatalf("ConfirmTOTPEnrollment: %v", err)
	}
	if factors, _ := f.svc.Factors(ctx, f.user.ID); !factors.TOTP || !factors.Any() {
		t.Error("confirmed TOTP not reported")
	}

	// The code used for confirmation can't be replayed.
	if err := f.svc.VerifyTOTP(ctx, f.user.ID, code()); err == nil {
		t.Error("replayed code accepted")
	}

	*f.clock = f.clock.Add(totpPeriod)
	if err := f.svc.VerifyTOTP(ctx, f.user.ID, code()); err != nil {
		t.Fatalf("VerifyTOTP with the next code: %v", err)
	}

	// A new enrollment is refused while one is active.
	if _, err := f.svc.StartTOTPEnrollment(ctx, f.user); err == nil {
		t.Error("second enrollment allowed while one is active")
	}
}

func TestFailedAttemptsLockTheUser(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	enrollment, _ := f.svc.StartTOTPEnrollment(ctx, f.user)
	code, _ := totp.GenerateCode(enrollment.Secret, *f.clock)
	if err := f.svc.ConfirmTOTPEnrollment(ctx, f.user, code); err != nil {
		t.Fatal(err)
	}

	for attempt := 1; attempt <= lockout.MaxAttempts; attempt++ {
		err := f.svc.VerifyTOTP(ctx, f.user.ID, "123456")
		p, ok := problem.As(err)
		if !ok {
			t.Fatalf("attempt %d: err = %v, want a problem", attempt, err)
		}
		if attempt < lockout.MaxAttempts && p.Kind != problem.KindInvalid {
			t.Errorf("attempt %d: kind %v, want invalid", attempt, p.Kind)
		}
		if attempt == lockout.MaxAttempts && (p.Kind != problem.KindForbidden || !strings.Contains(p.Message, "locked")) {
			t.Errorf("last attempt: %+v, want locked", p)
		}
	}

	user, _ := f.q.GetUser(ctx, f.user.ID)
	if user.LockedAt == nil {
		t.Fatal("user is not locked after too many failures")
	}
}

func TestSuccessResetsTheCounter(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	codes, err := f.svc.IssueRecoveryCodes(ctx, f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	for range lockout.MaxAttempts - 1 {
		_ = f.svc.VerifyRecoveryCode(ctx, f.user.ID, "WRONG-WRONG-WRONG-WRONG")
	}
	if err := f.svc.VerifyRecoveryCode(ctx, f.user.ID, codes[0]); err != nil {
		t.Fatalf("VerifyRecoveryCode: %v", err)
	}
	if user, _ := f.q.GetUser(ctx, f.user.ID); user.FailedMFAAttempts != 0 || user.LockedAt != nil {
		t.Errorf("counter not reset: %+v", user)
	}
}

func TestRecoveryCodes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	codes, err := f.svc.IssueRecoveryCodes(ctx, f.user.ID)
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatalf("IssueRecoveryCodes = %v, %v", codes, err)
	}

	// Codes are accepted in any case and without dashes, once.
	typed := strings.ToLower(strings.ReplaceAll(codes[3], "-", " "))
	if err := f.svc.VerifyRecoveryCode(ctx, f.user.ID, typed); err != nil {
		t.Fatalf("VerifyRecoveryCode: %v", err)
	}
	if err := f.svc.VerifyRecoveryCode(ctx, f.user.ID, codes[3]); err == nil {
		t.Error("a used recovery code was accepted again")
	}
	if factors, _ := f.svc.Factors(ctx, f.user.ID); factors.RecoveryCodesLeft != RecoveryCodeCount-1 {
		t.Errorf("codes left = %d", factors.RecoveryCodesLeft)
	}

	// Issuing again replaces the old codes.
	if _, err := f.svc.IssueRecoveryCodes(ctx, f.user.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.VerifyRecoveryCode(ctx, f.user.ID, codes[0]); err == nil {
		t.Error("an old recovery code still works after reissuing")
	}
}

func TestPasskeyCeremonyMustMatchPurpose(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	_, state, err := f.svc.BeginPasskeyRegistration(ctx, f.user)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}
	// A registration ceremony can't be used to finish a login.
	if err := f.svc.FinishPasskeyLogin(ctx, f.user, state, []byte(`{}`)); err == nil {
		t.Error("login finished with a registration ceremony")
	}
	if err := f.svc.FinishPasskeyRegistration(ctx, f.user, nil, []byte(`{}`), "key"); err == nil {
		t.Error("registration finished without a ceremony")
	}
	if _, _, err := f.svc.BeginPasskeyLogin(ctx, f.user); err == nil {
		t.Error("passkey login started for a user without passkeys")
	}
}

// Without a passkey origin passkeys are off, and the public URL's host
// doesn't have to be a valid passkey domain.
func TestPasskeysOff(t *testing.T) {
	f := newFixture(t)
	f.svc.webauthn = nil
	_, _, err := f.svc.BeginPasskeyRegistration(context.Background(), f.user)
	if p, ok := problem.As(err); !ok || p.Kind != problem.KindNotFound {
		t.Errorf("BeginPasskeyRegistration with passkeys off: %v", err)
	}
	if _, err := NewService(nil, nil, nil, nil, nil); err != nil {
		t.Errorf("NewService without passkeys: %v", err)
	}
}
