// Package items is what users do with parameters and secrets: list, search,
// view, reveal, create, edit, roll back and annotate them.
//
// Every operation checks the user's permissions first and records an audit
// event. Values only travel as sensitive.Value and are never stored.
package items

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"platypus/internal/audit"
	"platypus/internal/authz"
	"platypus/internal/catalog"
	"platypus/internal/item"
	"platypus/internal/problem"
	"platypus/internal/ratelimit"
	"platypus/internal/store"
)

// ErrBinarySecret marks a secret whose value is binary: platypus shows its
// metadata but can neither reveal nor change it.
var ErrBinarySecret = errors.New("binary secret")

// Service performs item operations.
type Service struct {
	catalog          *catalog.Catalog
	parameters       store.Parameters
	secrets          store.Secrets
	audit            *audit.Recorder
	limiter          *ratelimit.Limiter
	revealsPerMinute int
	terraformTags    []item.Tag
}

// Config holds item settings.
type Config struct {
	RevealsPerMinute int
	// TerraformTags mark items Terraform manages; platypus doesn't change them.
	TerraformTags []item.Tag
}

// NewService returns a Service.
func NewService(cat *catalog.Catalog, parameters store.Parameters, secrets store.Secrets,
	recorder *audit.Recorder, limiter *ratelimit.Limiter, cfg Config) *Service {
	return &Service{
		catalog:          cat,
		parameters:       parameters,
		secrets:          secrets,
		audit:            recorder,
		limiter:          limiter,
		revealsPerMinute: cfg.RevealsPerMinute,
		terraformTags:    cfg.TerraformTags,
	}
}

// notFound is the answer for items that don't exist, are hidden, or that the
// user may not list: all three look the same, so nothing leaks.
func notFound(kind item.Kind) error {
	return problem.NotFound("This %s doesn't exist, or you have no access to it.", kind.Noun())
}

// authorize checks permission p on an item and records a denial.
func (s *Service) authorize(ctx context.Context, subject authz.Subject, p authz.Permission,
	action audit.Action, kind item.Kind, name string) error {
	decision := subject.Can(p, kind, name)
	if decision.Allowed {
		return nil
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: action, Outcome: audit.Denied,
		Kind: string(kind), Name: name, Reason: decision.Reason})

	switch {
	case subject.Blocked, p == authz.Create:
		return problem.Forbidden("%s", decision.Reason)
	case p != authz.List && subject.Can(authz.List, kind, name).Allowed:
		return problem.Forbidden("%s", decision.Reason)
	default:
		// Users who can't list an item mustn't learn whether it exists.
		return notFound(kind)
	}
}

// entry loads an item the subject may list.
func (s *Service) entry(ctx context.Context, subject authz.Subject, action audit.Action,
	kind item.Kind, name string) (catalog.Entry, error) {
	if err := s.authorize(ctx, subject, authz.List, action, kind, name); err != nil {
		return catalog.Entry{}, err
	}
	entry, found, err := s.catalog.Get(ctx, kind, name)
	if err != nil {
		return catalog.Entry{}, err
	}
	if !found {
		return catalog.Entry{}, notFound(kind)
	}
	return entry, nil
}

// tagsOf returns an item's tags. SSM lists don't include tags, so they are
// fetched once and cached. When platypus may not read them the item has no
// known tags; tags are informational and must not hide the item.
func (s *Service) tagsOf(ctx context.Context, action audit.Action, entry catalog.Entry) (map[string]string, error) {
	if entry.Tags != nil || entry.Kind != item.KindSSM {
		return entry.Tags, nil
	}
	tags, err := s.parameters.Tags(ctx, entry.Name)
	switch {
	case err == nil:
		return tags, s.catalog.SetTags(ctx, entry.Kind, entry.Name, tags)
	case errors.Is(err, store.ErrAccessDenied):
		return nil, nil
	default:
		return nil, s.storeError(ctx, action, entry.Kind, entry.Name, err)
	}
}

// managedByTerraform reports whether Terraform manages the item.
func (s *Service) managedByTerraform(tags map[string]string) bool {
	return item.HasAnyTag(tags, s.terraformTags)
}

// refuseTerraformManaged stops changes to the value or settings of items
// Terraform manages: Terraform would undo them, so they belong there.
func (s *Service) refuseTerraformManaged(ctx context.Context, action audit.Action, entry catalog.Entry) error {
	tags, err := s.tagsOf(ctx, action, entry)
	if err != nil {
		return err
	}
	if !s.managedByTerraform(tags) {
		return nil
	}
	reason := terraformReason(entry.Kind)
	s.audit.RecordBestEffort(ctx, audit.Event{Action: action, Outcome: audit.Denied,
		Kind: string(entry.Kind), Name: entry.Name, Reason: reason})
	return problem.Forbidden("%s", reason)
}

func terraformReason(kind item.Kind) string {
	return "This " + kind.Noun() + " is managed by Terraform. Change it in Terraform; a change made here would be undone."
}

// storeError turns a store error into what the user should see, and keeps
// the cache in line: items AWS denies platypus are hidden from now on.
func (s *Service) storeError(ctx context.Context, action audit.Action, kind item.Kind, name string, err error) error {
	var rejected *store.RejectedError
	if _, isProblem := problem.As(err); isProblem || err == nil {
		return err
	}
	switch {
	case errors.Is(err, store.ErrAccessDenied):
		if markErr := s.catalog.SetAccess(ctx, kind, name, catalog.AccessDenied); markErr != nil {
			return markErr
		}
		s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionItemHidden, Outcome: audit.Error,
			Kind: string(kind), Name: name, Reason: "AWS denied platypus access; the item is hidden from now on"})
		return notFound(kind)
	case errors.Is(err, store.ErrNotFound):
		return problem.NotFound("This %s no longer exists in AWS.", kind.Noun())
	case errors.Is(err, store.ErrConflict):
		return problem.Conflict("Someone changed this %s while you were editing. Reload the page to see the latest version.", kind.Noun())
	case errors.Is(err, store.ErrAlreadyExists):
		return problem.Conflict("A %s with this name exists already.", kind.Noun())
	case errors.Is(err, store.ErrBinaryValue):
		return errors.Join(ErrBinarySecret, problem.Invalid("This secret holds binary data, which platypus doesn't support."))
	case errors.As(err, &rejected):
		return problem.Invalid("AWS refused this: %s", rejected.Message)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: action, Outcome: audit.Error,
		Kind: string(kind), Name: name, Reason: "AWS call failed"})
	return fmt.Errorf("%s %s: %w", action, name, err)
}

// refresh reads an item back from AWS after platypus changed it and updates
// the cache, so lists show the change right away. It is stamped with the
// database clock, which the sync compares against.
func (s *Service) refresh(ctx context.Context, kind item.Kind, name string) error {
	switch kind {
	case item.KindSSM:
		p, err := s.parameters.Describe(ctx, name)
		if err != nil {
			return err
		}
		return s.catalog.PutParameter(ctx, p, catalog.AccessOK, time.Time{})
	case item.KindSecret:
		sec, err := s.secrets.Describe(ctx, name)
		if err != nil {
			return err
		}
		return s.catalog.PutSecret(ctx, sec, catalog.AccessOK, time.Time{})
	default:
		return unknownKind(kind)
	}
}

// unknownKind guards the kind switches: a new kind must be handled
// everywhere, never fall through to another kind's store.
func unknownKind(kind item.Kind) error {
	return fmt.Errorf("unknown item kind %q", kind)
}

// secretVersionID is the shape of a Secrets Manager version ID.
var secretVersionID = regexp.MustCompile(`^[A-Za-z0-9_-]{32,64}$`)

func checkSecretVersionID(id string) error {
	if !secretVersionID.MatchString(id) {
		return problem.Invalid("%q is not a secret version.", id)
	}
	return nil
}
