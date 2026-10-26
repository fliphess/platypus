// Package lockout counts failed second-factor attempts and locks a user out
// after too many in a row.
//
// TOTP codes, passkeys, recovery codes and bootstrap tokens share one
// counter. A locked user can't use platypus at all until an admin unlocks
// them, or someone clears users.locked_at with psql.
package lockout

import (
	"context"
	"fmt"

	"platypus/internal/audit"
	"platypus/internal/db"
	"platypus/internal/problem"
)

// MaxAttempts is the number of failures in a row that locks a user.
const MaxAttempts = 5

// Guard records attempts.
type Guard struct {
	queries *db.Queries
	audit   *audit.Recorder
}

// NewGuard returns a Guard.
func NewGuard(queries *db.Queries, recorder *audit.Recorder) *Guard {
	return &Guard{queries: queries, audit: recorder}
}

// Failed records a failed attempt at what ("TOTP code", "passkey", ...) and
// returns the problem to show the user.
func (g *Guard) Failed(ctx context.Context, userID int64, what string) error {
	result, err := g.queries.RecordFailedAttempt(ctx, db.RecordFailedAttemptParams{ID: userID, MaxAttempts: MaxAttempts})
	if err != nil {
		return fmt.Errorf("record failed attempt: %w", err)
	}
	g.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionMFAFailed, Outcome: audit.Denied,
		Reason: what + " not accepted", Details: map[string]any{"attempt": result.FailedMFAAttempts}})

	if result.LockedAt != nil {
		g.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionUserLocked, Outcome: audit.Denied,
			Reason: fmt.Sprintf("%d failed attempts in a row", result.FailedMFAAttempts)})
		return problem.Forbidden("Too many failed attempts: your account is now locked. Ask an admin to unlock it.")
	}
	left := MaxAttempts - int(result.FailedMFAAttempts)
	return problem.Invalid("That %s was not accepted. %d more failed attempts lock your account.", what, left)
}

// Succeeded resets the counter after a successful attempt.
func (g *Guard) Succeeded(ctx context.Context, userID int64) error {
	if err := g.queries.ResetFailedAttempts(ctx, userID); err != nil {
		return fmt.Errorf("reset failed attempts: %w", err)
	}
	return nil
}
