package items

import (
	"context"
	"time"

	"platypus/internal/audit"
	"platypus/internal/authz"
	"platypus/internal/catalog"
	"platypus/internal/item"
	"platypus/internal/problem"
)

// Undelete cancels a secret's scheduled deletion, so it can be read and
// changed again. It needs edit permission and is audited like any change.
func (s *Service) Undelete(ctx context.Context, subject authz.Subject, name string) error {
	entry, err := s.entry(ctx, subject, audit.ActionItemUndelete, item.KindSecret, name)
	if err != nil {
		return err
	}
	if err := s.authorize(ctx, subject, authz.Edit, audit.ActionItemUndelete, item.KindSecret, name); err != nil {
		return err
	}
	if entry.DeletedAt == nil {
		return problem.Invalid("This secret isn't scheduled for deletion.")
	}
	if err := s.secrets.Undelete(ctx, name); err != nil {
		return s.storeError(ctx, audit.ActionItemUndelete, item.KindSecret, name, err)
	}
	// The AWS outcome is recorded before any reconciliation: a cache problem
	// must not hide a restore that already happened.
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionItemUndelete, Outcome: audit.Allowed,
		Kind: string(item.KindSecret), Name: name})
	if fresh, err := s.secrets.Describe(ctx, name); err == nil {
		// Zero time means "let the database set synced_at" (its clock).
		_ = s.catalog.PutSecret(ctx, fresh, catalog.AccessOK, time.Time{})
	}
	return nil
}
