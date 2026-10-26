package mfa

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"image/png"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"platypus/internal/audit"
	"platypus/internal/database"
	"platypus/internal/db"
	"platypus/internal/problem"
)

const (
	totpPeriod = 30 * time.Second
	totpIssuer = "Platypus"
)

var totpOptions = totp.ValidateOpts{Period: uint(totpPeriod.Seconds()), Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

// TOTPEnrollment is what the user needs to add platypus to an authenticator
// app. Secret is shown for manual entry; QRCode is a PNG data URI.
type TOTPEnrollment struct {
	Secret string
	QRCode string
}

// StartTOTPEnrollment generates a new TOTP secret and stores it unconfirmed.
// A confirmed TOTP has to be removed before a new one can be enrolled.
func (s *Service) StartTOTPEnrollment(ctx context.Context, user db.User) (TOTPEnrollment, error) {
	existing, err := s.queries.GetTOTP(ctx, user.ID)
	if err == nil && existing.ConfirmedAt != nil {
		return TOTPEnrollment{}, problem.Conflict("You already have an authenticator app set up; remove it first.")
	}
	if err != nil && !database.IsNoRows(err) {
		return TOTPEnrollment{}, fmt.Errorf("load TOTP: %w", err)
	}

	key, err := totp.Generate(totp.GenerateOpts{Issuer: totpIssuer, AccountName: user.Email})
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("generate TOTP secret: %w", err)
	}
	sealed, err := s.sealer.Seal([]byte(key.Secret()), userContext(user.ID))
	if err != nil {
		return TOTPEnrollment{}, err
	}
	err = s.queries.SavePendingTOTP(ctx, db.SavePendingTOTPParams{
		UserID:           user.ID,
		SecretCiphertext: sealed,
		KeyID:            s.sealer.KeyID(),
	})
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("save TOTP secret: %w", err)
	}

	image, err := key.Image(240, 240)
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("render QR code: %w", err)
	}
	var qr bytes.Buffer
	if err := png.Encode(&qr, image); err != nil {
		return TOTPEnrollment{}, fmt.Errorf("encode QR code: %w", err)
	}
	return TOTPEnrollment{
		Secret: key.Secret(),
		QRCode: "data:image/png;base64," + base64.StdEncoding.EncodeToString(qr.Bytes()),
	}, nil
}

// ConfirmTOTPEnrollment activates a pending TOTP secret with a first code.
func (s *Service) ConfirmTOTPEnrollment(ctx context.Context, user db.User, code string) error {
	step, err := s.matchTOTP(ctx, user.ID, code, false)
	if err != nil {
		return err
	}
	if step == 0 {
		return problem.Invalid("That code doesn't match. Check the time on your phone and try the next code.")
	}
	if err := s.useStep(ctx, user.ID, step); err != nil {
		return err
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionTOTPEnrolled, Outcome: audit.Allowed})
	return nil
}

// VerifyTOTP checks a code for admin mode. Each code works once; failures
// count towards the lockout.
func (s *Service) VerifyTOTP(ctx context.Context, userID int64, code string) error {
	step, err := s.matchTOTP(ctx, userID, code, true)
	if err != nil {
		return err
	}
	if step == 0 {
		return s.guard.Failed(ctx, userID, "authenticator code")
	}
	if err := s.useStep(ctx, userID, step); err != nil {
		return s.guard.Failed(ctx, userID, "authenticator code")
	}
	return s.guard.Succeeded(ctx, userID)
}

// RemoveTOTP removes the authenticator app.
func (s *Service) RemoveTOTP(ctx context.Context, userID int64) error {
	if err := s.queries.DeleteTOTP(ctx, userID); err != nil {
		return fmt.Errorf("remove TOTP: %w", err)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionTOTPRemoved, Outcome: audit.Allowed})
	return nil
}

// matchTOTP returns the time step the code belongs to, allowing one step of
// clock drift either way, or 0 when it doesn't match. confirmed selects
// whether an active or a pending secret is checked.
func (s *Service) matchTOTP(ctx context.Context, userID int64, code string, confirmed bool) (int64, error) {
	cred, err := s.queries.GetTOTP(ctx, userID)
	if database.IsNoRows(err) || (err == nil && (cred.ConfirmedAt != nil) != confirmed) {
		if confirmed {
			return 0, problem.Invalid("You have no authenticator app set up.")
		}
		return 0, problem.Invalid("Start setting up the authenticator app first.")
	}
	if err != nil {
		return 0, fmt.Errorf("load TOTP: %w", err)
	}
	secret, err := s.sealer.Open(cred.SecretCiphertext, userContext(userID), cred.KeyID)
	if err != nil {
		return 0, fmt.Errorf("open TOTP secret: %w", err)
	}

	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, nil
	}
	now := s.now()
	for _, drift := range []time.Duration{0, -totpPeriod, totpPeriod} {
		at := now.Add(drift)
		want, err := totp.GenerateCodeCustom(string(secret), at, totpOptions)
		if err != nil {
			return 0, fmt.Errorf("generate TOTP code: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return at.Unix() / int64(totpPeriod.Seconds()), nil
		}
	}
	return 0, nil
}

// useStep marks a time step as used. It fails when the step, or a later one,
// was used before: the same code can't be replayed.
func (s *Service) useStep(ctx context.Context, userID, step int64) error {
	_, err := s.queries.UseTOTPStep(ctx, db.UseTOTPStepParams{UserID: userID, Step: step})
	if database.IsNoRows(err) {
		return problem.Invalid("That code was used already; wait for the next one.")
	}
	return err
}
