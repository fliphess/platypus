package items

import (
	"context"
	"strconv"
	"time"

	"platypus/internal/audit"
	"platypus/internal/authz"
	"platypus/internal/item"
	"platypus/internal/problem"
	"platypus/internal/sensitive"
)

// Reveal returns the value of an item for the subject to see. version is an
// ID from History; empty means the current value. The reveal is recorded in
// the audit trail before the value is returned, and not returned when that
// fails.
func (s *Service) Reveal(ctx context.Context, subject authz.Subject, kind item.Kind, name, version string) (sensitive.Value, error) {
	return s.reveal(ctx, subject, kind, name, version, "view")
}

// RevealForEditing returns the current value to pre-fill the editor. It needs
// the same permission as Reveal and is audited the same way.
func (s *Service) RevealForEditing(ctx context.Context, subject authz.Subject, kind item.Kind, name string) (sensitive.Value, error) {
	return s.reveal(ctx, subject, kind, name, "", "edit")
}

func (s *Service) reveal(ctx context.Context, subject authz.Subject, kind item.Kind, name, version, purpose string) (sensitive.Value, error) {
	entry, err := s.entry(ctx, subject, audit.ActionItemReveal, kind, name)
	if err != nil {
		return sensitive.Value{}, err
	}
	if entry.DeletedAt != nil {
		return sensitive.Value{}, problem.Invalid("This secret is scheduled for deletion; restore it first, then read it.")
	}
	if err := s.authorize(ctx, subject, authz.Reveal, audit.ActionItemReveal, kind, name); err != nil {
		return sensitive.Value{}, err
	}

	userID := audit.ActorFrom(ctx).UserID
	allowed, err := s.limiter.Allow(ctx, "reveal:"+strconv.FormatInt(userID, 10), s.revealsPerMinute, time.Minute)
	if err != nil {
		return sensitive.Value{}, err
	}
	if !allowed {
		s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionItemReveal, Outcome: audit.Denied,
			Kind: string(kind), Name: name, Reason: "rate limit"})
		return sensitive.Value{}, problem.TooManyRequests("You revealed %d values in the last minute. Wait a moment and try again.", s.revealsPerMinute)
	}

	value, err := s.readValue(ctx, kind, name, version)
	if err != nil {
		return sensitive.Value{}, s.storeError(ctx, audit.ActionItemReveal, kind, name, err)
	}

	details := map[string]any{"purpose": purpose}
	if version != "" {
		details["version"] = version
	}
	err = s.audit.Record(ctx, audit.Event{Action: audit.ActionItemReveal, Outcome: audit.Allowed,
		Kind: string(kind), Name: name, Details: details})
	if err != nil {
		return sensitive.Value{}, err
	}
	return value, nil
}

// readValue reads a value from AWS without any checks.
func (s *Service) readValue(ctx context.Context, kind item.Kind, name, version string) (sensitive.Value, error) {
	switch kind {
	case item.KindSSM:
		var number int64
		if version != "" {
			n, err := strconv.ParseInt(version, 10, 64)
			if err != nil || n < 1 {
				return sensitive.Value{}, problem.Invalid("%q is not a parameter version.", version)
			}
			number = n
		}
		return s.parameters.Value(ctx, name, number)
	case item.KindSecret:
		if version != "" {
			if err := checkSecretVersionID(version); err != nil {
				return sensitive.Value{}, err
			}
		}
		return s.secrets.Value(ctx, name, version)
	default:
		return sensitive.Value{}, unknownKind(kind)
	}
}
