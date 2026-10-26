package bootstrap

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"platypus/internal/db"
	"platypus/internal/mfa"
)

func confirmTOTP(t *testing.T, svc *mfa.Service, user db.User, secret string) {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ConfirmTOTPEnrollment(context.Background(), user, code); err != nil {
		t.Fatalf("ConfirmTOTPEnrollment: %v", err)
	}
}
