package mfa

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"

	"platypus/internal/audit"
	"platypus/internal/database"
	"platypus/internal/db"
	"platypus/internal/secrethash"
)

// RecoveryCodeCount is how many recovery codes a user gets at a time.
const RecoveryCodeCount = 10

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// IssueRecoveryCodes replaces all recovery codes of a user with new ones and
// returns them. They are shown once and only their hashes are kept.
func (s *Service) IssueRecoveryCodes(ctx context.Context, userID int64) ([]string, error) {
	codes := make([]string, RecoveryCodeCount)
	hashes := make([]string, RecoveryCodeCount)
	for i := range codes {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, err
		}
		hash, err := secrethash.Hash(normalizeRecoveryCode(code))
		if err != nil {
			return nil, err
		}
		codes[i], hashes[i] = code, hash
	}

	err := database.InTx(ctx, s.pool, func(q *db.Queries) error {
		if err := q.DeleteRecoveryCodes(ctx, userID); err != nil {
			return err
		}
		for _, hash := range hashes {
			if err := q.InsertRecoveryCode(ctx, db.InsertRecoveryCodeParams{UserID: userID, CodeHash: hash}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store recovery codes: %w", err)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionRecoveryCodesIssue, Outcome: audit.Allowed})
	return codes, nil
}

// VerifyRecoveryCode checks a recovery code for admin mode and uses it up.
// Failures count towards the lockout.
func (s *Service) VerifyRecoveryCode(ctx context.Context, userID int64, code string) error {
	candidates, err := s.queries.ListUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		return fmt.Errorf("load recovery codes: %w", err)
	}
	normalized := normalizeRecoveryCode(code)
	for _, candidate := range candidates {
		if !secrethash.Verify(normalized, candidate.CodeHash) {
			continue
		}
		if _, err := s.queries.UseRecoveryCode(ctx, candidate.ID); err != nil {
			// Used by a concurrent request a moment ago.
			return s.guard.Failed(ctx, userID, "recovery code")
		}
		s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionRecoveryCodeUsed, Outcome: audit.Allowed,
			Details: map[string]any{"codes_left": len(candidates) - 1}})
		return s.guard.Succeeded(ctx, userID)
	}
	return s.guard.Failed(ctx, userID, "recovery code")
}

// newRecoveryCode returns a code like ABCDE-FGHIJ-KLMNO-PQRST (100 bits).
func newRecoveryCode() (string, error) {
	b := make([]byte, 13)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate recovery code: %w", err)
	}
	raw := recoveryEncoding.EncodeToString(b)[:20]
	return raw[0:5] + "-" + raw[5:10] + "-" + raw[10:15] + "-" + raw[15:20], nil
}

// normalizeRecoveryCode accepts codes typed with any case, spaces or dashes.
func normalizeRecoveryCode(code string) string {
	code = strings.ToUpper(code)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, code)
}
