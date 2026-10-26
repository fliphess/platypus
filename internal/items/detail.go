package items

import (
	"context"
	"strconv"
	"time"

	"platypus/internal/audit"
	"platypus/internal/authz"
	"platypus/internal/catalog"
	"platypus/internal/item"
	"platypus/internal/store"
)

// Detail is an item as shown on its own page.
type Detail struct {
	catalog.Entry
	Note *catalog.Note
	// Permissions are what the subject may do with this item right now.
	Permissions authz.Permissions
	// Denials explain each permission the subject lacks, for disabled buttons.
	Denials map[authz.Permission]string
	// TerraformManaged items can't be changed here; Edit then only covers the note.
	TerraformManaged bool
	TerraformReason  string
}

// Get returns an item's details and records that the subject viewed it.
func (s *Service) Get(ctx context.Context, subject authz.Subject, kind item.Kind, name string) (Detail, error) {
	entry, err := s.entry(ctx, subject, audit.ActionItemView, kind, name)
	if err != nil {
		return Detail{}, err
	}

	if entry.Tags, err = s.tagsOf(ctx, audit.ActionItemView, entry); err != nil {
		return Detail{}, err
	}

	note, err := s.catalog.Note(ctx, kind, name)
	if err != nil {
		return Detail{}, err
	}

	detail := Detail{
		Entry:       entry,
		Note:        note,
		Permissions: authz.Permissions{List: true},
		Denials:     map[authz.Permission]string{},
	}
	if decision := subject.Can(authz.Edit, kind, name); decision.Allowed {
		detail.Permissions.Edit = true
	} else {
		detail.Denials[authz.Edit] = decision.Reason
	}
	if decision := subject.Can(authz.Reveal, kind, name); decision.Allowed {
		detail.Permissions.Reveal = true
	} else {
		detail.Denials[authz.Reveal] = decision.Reason
	}
	if s.managedByTerraform(entry.Tags) {
		detail.TerraformManaged = true
		detail.TerraformReason = terraformReason(kind)
	}

	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionItemView, Outcome: audit.Allowed,
		Kind: string(kind), Name: name})
	return detail, nil
}

// Version is one version of an item, without its value.
type Version struct {
	// ID identifies the version for reveal and rollback: the SSM version
	// number or the secret version id.
	ID          string
	Label       string
	Created     time.Time
	CreatedBy   string
	Description string
	Current     bool
	Stages      []string
}

// History returns the versions of an item, newest first.
func (s *Service) History(ctx context.Context, subject authz.Subject, kind item.Kind, name string) ([]Version, error) {
	entry, err := s.entry(ctx, subject, audit.ActionItemView, kind, name)
	if err != nil {
		return nil, err
	}

	switch kind {
	case item.KindSSM:
		history, err := s.parameters.History(ctx, name)
		if err != nil {
			return nil, s.storeError(ctx, audit.ActionItemView, kind, name, err)
		}
		versions := make([]Version, len(history))
		for i, h := range history {
			versions[i] = Version{
				ID:          strconv.FormatInt(h.Version, 10),
				Label:       "Version " + strconv.FormatInt(h.Version, 10),
				Created:     h.LastModified,
				CreatedBy:   h.LastModifiedBy,
				Description: h.Description,
				Current:     h.Version == entry.SSMVersion,
				Stages:      h.Labels,
			}
		}
		return versions, nil
	case item.KindSecret:
	default:
		return nil, unknownKind(kind)
	}

	secretVersions, err := s.secrets.Versions(ctx, name)
	if err != nil {
		return nil, s.storeError(ctx, audit.ActionItemView, kind, name, err)
	}
	versions := make([]Version, len(secretVersions))
	for i, v := range secretVersions {
		versions[i] = Version{
			ID:      v.ID,
			Label:   secretVersionLabel(v),
			Created: v.Created,
			Current: v.IsCurrent(),
			Stages:  v.Stages,
		}
	}
	return versions, nil
}

func secretVersionLabel(v store.SecretVersion) string {
	short := v.ID
	if len(short) > 8 {
		short = short[:8]
	}
	return "Version " + short
}
