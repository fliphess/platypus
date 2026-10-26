package items

import (
	"context"
	"slices"
	"strconv"

	"platypus/internal/audit"
	"platypus/internal/authz"
	"platypus/internal/catalog"
	"platypus/internal/item"
	"platypus/internal/problem"
	"platypus/internal/sensitive"
	"platypus/internal/store"
	"platypus/internal/textclean"
)

// Tags platypus puts on everything it creates.
const (
	TagTerraform = "Terraform"
	TagManagedBy = "ManagedBy"
	TagCreatedBy = "CreatedBy"
	TagTeam      = "Team"
)

// NewItem is a parameter or secret to create.
type NewItem struct {
	Kind        item.Kind
	Name        string
	Value       sensitive.Value
	IsJSON      bool
	Description string
	SSMType     string
	SSMTier     string
	// Team goes into the Team tag; it must be one of the creator's teams.
	Team string
}

// Change is an edit of an existing item. Settings are the full new state as
// submitted by the edit form; Value is nil when the value stays as it is.
type Change struct {
	Kind          item.Kind
	Name          string
	Value         *sensitive.Value
	IsJSON        bool
	Description   string
	SSMType       string
	SSMTier       string
	ExpectVersion string
}

// Summary describes a change for the confirmation step. It never holds values.
type Summary struct {
	Kind     item.Kind
	Name     string
	IsNew    bool
	Value    string // "new", "replaced" or "" (unchanged)
	JSONKeys *KeyChanges
	Settings []SettingChange
	Tags     map[string]string
	Note     *catalog.Note
	Warnings []string
}

// SettingChange is one changed setting.
type SettingChange struct {
	Setting string
	Before  string
	After   string
}

// PreviewCreate validates a new item and describes it for confirmation.
func (s *Service) PreviewCreate(ctx context.Context, subject authz.Subject, creatorTeams []string, n NewItem) (Summary, error) {
	n, tags, err := s.prepareCreate(ctx, subject, creatorTeams, n)
	if err != nil {
		return Summary{}, err
	}
	summary := Summary{Kind: n.Kind, Name: n.Name, IsNew: true, Value: "new", Tags: tags}
	if n.Description != "" {
		summary.Settings = append(summary.Settings, SettingChange{Setting: "Description", After: n.Description})
	}
	if n.Kind == item.KindSSM {
		summary.Settings = append(summary.Settings,
			SettingChange{Setting: "Type", After: n.SSMType},
			SettingChange{Setting: "Tier", After: n.SSMTier})
	}
	return summary, nil
}

// Create creates a parameter or secret. It never overwrites an existing one.
func (s *Service) Create(ctx context.Context, subject authz.Subject, creatorTeams []string, n NewItem) error {
	n, tags, err := s.prepareCreate(ctx, subject, creatorTeams, n)
	if err != nil {
		return err
	}

	switch n.Kind {
	case item.KindSSM:
		_, err = s.parameters.Create(ctx, store.NewParameter{
			Name: n.Name, Value: n.Value, Type: n.SSMType, Tier: n.SSMTier, Description: n.Description, Tags: tags,
		})
	case item.KindSecret:
		_, err = s.secrets.Create(ctx, store.NewSecret{Name: n.Name, Value: n.Value, Description: n.Description, Tags: tags})
	}
	if err != nil {
		return s.storeError(ctx, audit.ActionItemCreate, n.Kind, n.Name, err)
	}

	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionItemCreate, Outcome: audit.Allowed,
		Kind: string(n.Kind), Name: n.Name,
		Details: map[string]any{"type": n.SSMType, "tier": n.SSMTier, "tags": tags}})
	return s.refresh(ctx, n.Kind, n.Name)
}

// prepareCreate checks permissions and input and returns the cleaned item
// with the tags to set.
func (s *Service) prepareCreate(ctx context.Context, subject authz.Subject, creatorTeams []string, n NewItem) (NewItem, map[string]string, error) {
	if err := item.ValidateName(n.Kind, n.Name); err != nil {
		return NewItem{}, nil, problem.Invalid("Name: %v.", err)
	}
	if err := s.authorize(ctx, subject, authz.Create, audit.ActionItemCreate, n.Kind, n.Name); err != nil {
		return NewItem{}, nil, err
	}
	description, err := cleanDescription(n.Description)
	if err != nil {
		return NewItem{}, nil, err
	}
	n.Description = description

	if n.Kind == item.KindSSM {
		if err := validateSSMSettings(n.SSMType, n.SSMTier); err != nil {
			return NewItem{}, nil, err
		}
	} else {
		n.SSMType, n.SSMTier = "", ""
	}
	if err := validateValue(n.Kind, n.SSMTier, n.Value, n.IsJSON); err != nil {
		return NewItem{}, nil, err
	}

	tags := map[string]string{
		TagTerraform: "false",
		TagManagedBy: "platypus",
		TagCreatedBy: audit.ActorFrom(ctx).Email,
	}
	if n.Team != "" {
		if !slices.Contains(creatorTeams, n.Team) {
			return NewItem{}, nil, problem.Invalid("You're not a member of team %q.", n.Team)
		}
		tags[TagTeam] = n.Team
	}
	return n, tags, nil
}

// PreviewUpdate validates a change and describes it for confirmation.
func (s *Service) PreviewUpdate(ctx context.Context, subject authz.Subject, c Change) (Summary, error) {
	entry, c, err := s.prepareUpdate(ctx, subject, c)
	if err != nil {
		return Summary{}, err
	}
	summary := Summary{Kind: c.Kind, Name: c.Name, Settings: settingChanges(entry, c)}

	if c.Value != nil {
		summary.Value = "replaced"
		// Users who may reveal see which JSON keys change; others only learn
		// the value is replaced, not what it held.
		if c.IsJSON && subject.Can(authz.Reveal, c.Kind, c.Name).Allowed {
			if current, err := s.readValue(ctx, c.Kind, c.Name, ""); err == nil {
				if keys, ok := compareJSONKeys(current, *c.Value); ok {
					summary.JSONKeys = &keys
				}
			}
		}
	}
	if c.Value == nil && len(summary.Settings) == 0 {
		return Summary{}, problem.Invalid("Nothing changed.")
	}

	if summary.Note, err = s.catalog.Note(ctx, c.Kind, c.Name); err != nil {
		return Summary{}, err
	}
	if entry.RotationEnabled && c.Value != nil {
		summary.Warnings = append(summary.Warnings,
			"Rotation is enabled for this secret: the next rotation will replace the value you set.")
	}
	if c.Kind == item.KindSSM && c.Value == nil {
		summary.Warnings = append(summary.Warnings,
			"SSM can only change these settings by writing the value again, so this creates a new version with the same value.")
	}
	return summary, nil
}

// Update applies a change. The value is only touched when Value is set.
func (s *Service) Update(ctx context.Context, subject authz.Subject, c Change) error {
	entry, c, err := s.prepareUpdate(ctx, subject, c)
	if err != nil {
		return err
	}
	changed := settingChanges(entry, c)
	if c.Value == nil && len(changed) == 0 {
		return problem.Invalid("Nothing changed.")
	}

	switch c.Kind {
	case item.KindSSM:
		err = s.updateParameter(ctx, c)
	case item.KindSecret:
		err = s.updateSecret(ctx, entry, c)
	default:
		err = unknownKind(c.Kind)
	}
	if err != nil {
		return s.storeError(ctx, audit.ActionItemUpdate, c.Kind, c.Name, err)
	}

	fields := make([]string, 0, len(changed)+1)
	if c.Value != nil {
		fields = append(fields, "value")
	}
	settings := map[string]any{}
	for _, change := range changed {
		fields = append(fields, change.Setting)
		settings[change.Setting] = map[string]string{"before": change.Before, "after": change.After}
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionItemUpdate, Outcome: audit.Allowed,
		Kind: string(c.Kind), Name: c.Name,
		Details: map[string]any{"changed": fields, "settings": settings, "from_version": c.ExpectVersion}})
	return s.refresh(ctx, c.Kind, c.Name)
}

func (s *Service) updateParameter(ctx context.Context, c Change) error {
	expect, err := strconv.ParseInt(c.ExpectVersion, 10, 64)
	if err != nil {
		return problem.Invalid("The edit form is outdated; reload the page.")
	}
	value := c.Value
	if value == nil {
		// SSM needs the value to change settings; it stays the same.
		current, err := s.parameters.Value(ctx, c.Name, expect)
		if err != nil {
			return err
		}
		value = &current
	}
	_, err = s.parameters.Update(ctx, store.ParameterUpdate{
		Name: c.Name, Value: *value, Type: c.SSMType, Tier: c.SSMTier,
		Description: c.Description, ExpectVersion: expect,
	})
	return err
}

func (s *Service) updateSecret(ctx context.Context, entry catalog.Entry, c Change) error {
	expect := c.ExpectVersion
	if c.Value != nil {
		// Platypus doesn't support binary secrets; don't overwrite one.
		if _, err := s.secrets.Value(ctx, c.Name, ""); err != nil {
			return err
		}
		updated, err := s.secrets.PutValue(ctx, c.Name, *c.Value, expect)
		if err != nil {
			return err
		}
		expect = updated.CurrentVersionID
	}
	if c.Description != entry.Description {
		return s.secrets.UpdateDescription(ctx, c.Name, c.Description, expect)
	}
	return nil
}

// prepareUpdate checks permissions and input and returns the current entry
// with the cleaned change.
func (s *Service) prepareUpdate(ctx context.Context, subject authz.Subject, c Change) (catalog.Entry, Change, error) {
	entry, err := s.entry(ctx, subject, audit.ActionItemUpdate, c.Kind, c.Name)
	if err != nil {
		return catalog.Entry{}, Change{}, err
	}
	if err := s.authorize(ctx, subject, authz.Edit, audit.ActionItemUpdate, c.Kind, c.Name); err != nil {
		return catalog.Entry{}, Change{}, err
	}
	if err := s.refuseTerraformManaged(ctx, audit.ActionItemUpdate, entry); err != nil {
		return catalog.Entry{}, Change{}, err
	}
	if entry.DeletedAt != nil {
		return catalog.Entry{}, Change{}, problem.Invalid("This secret is scheduled for deletion; restore it first, then change it.")
	}
	if c.ExpectVersion == "" {
		return catalog.Entry{}, Change{}, problem.Invalid("The edit form is outdated; reload the page.")
	}

	description, err := cleanDescription(c.Description)
	if err != nil {
		return catalog.Entry{}, Change{}, err
	}
	c.Description = description

	if c.Kind == item.KindSSM {
		if err := validateSSMSettings(c.SSMType, c.SSMTier); err != nil {
			return catalog.Entry{}, Change{}, err
		}
		if entry.SSMTier == item.SSMTierAdvanced && c.SSMTier == item.SSMTierStandard {
			return catalog.Entry{}, Change{}, problem.Invalid("AWS can't move a parameter from the Advanced tier back to Standard.")
		}
	} else {
		c.SSMType, c.SSMTier = "", ""
	}
	if c.Value != nil {
		if err := validateValue(c.Kind, c.SSMTier, *c.Value, c.IsJSON); err != nil {
			return catalog.Entry{}, Change{}, err
		}
		// The editor shows users who may reveal the current value; submitting
		// it unchanged is not a value change. Others never get this
		// comparison: it would tell them whether a guess was right.
		if subject.Can(authz.Reveal, c.Kind, c.Name).Allowed {
			current, err := s.readValue(ctx, c.Kind, c.Name, "")
			if err == nil && current.Reveal() == c.Value.Reveal() {
				c.Value = nil
			}
		}
	}
	return entry, c, nil
}

// settingChanges lists the settings a change modifies.
func settingChanges(entry catalog.Entry, c Change) []SettingChange {
	var changes []SettingChange
	if c.Description != entry.Description {
		changes = append(changes, SettingChange{Setting: "Description", Before: entry.Description, After: c.Description})
	}
	if c.Kind == item.KindSSM {
		if c.SSMType != entry.SSMType {
			changes = append(changes, SettingChange{Setting: "Type", Before: entry.SSMType, After: c.SSMType})
		}
		if c.SSMTier != entry.SSMTier {
			changes = append(changes, SettingChange{Setting: "Tier", Before: entry.SSMTier, After: c.SSMTier})
		}
	}
	return changes
}

// Rollback makes an earlier version current again: for secrets by moving
// the AWSCURRENT label, for parameters by writing the old value as a new
// version. The value is never shown.
func (s *Service) Rollback(ctx context.Context, subject authz.Subject, kind item.Kind, name, versionID, expectVersion string) error {
	entry, err := s.entry(ctx, subject, audit.ActionItemRollback, kind, name)
	if err != nil {
		return err
	}
	if entry.DeletedAt != nil {
		return problem.Invalid("This secret is scheduled for deletion; restore it first, then roll back.")
	}
	if err := s.authorize(ctx, subject, authz.Edit, audit.ActionItemRollback, kind, name); err != nil {
		return err
	}
	if err := s.refuseTerraformManaged(ctx, audit.ActionItemRollback, entry); err != nil {
		return err
	}

	switch kind {
	case item.KindSSM:
		err = s.rollbackParameter(ctx, entry, versionID, expectVersion)
	case item.KindSecret:
		if err := checkSecretVersionID(versionID); err != nil {
			return err
		}
		err = s.secrets.Restore(ctx, name, versionID, expectVersion)
	default:
		err = unknownKind(kind)
	}
	if err != nil {
		return s.storeError(ctx, audit.ActionItemRollback, kind, name, err)
	}

	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionItemRollback, Outcome: audit.Allowed,
		Kind: string(kind), Name: name,
		Details: map[string]any{"to_version": versionID, "from_version": expectVersion}})
	return s.refresh(ctx, kind, name)
}

func (s *Service) rollbackParameter(ctx context.Context, entry catalog.Entry, versionID, expectVersion string) error {
	target, err := strconv.ParseInt(versionID, 10, 64)
	if err != nil {
		return problem.Invalid("%q is not a parameter version.", versionID)
	}
	expect, err := strconv.ParseInt(expectVersion, 10, 64)
	if err != nil {
		return problem.Invalid("The page is outdated; reload it.")
	}
	history, err := s.parameters.History(ctx, entry.Name)
	if err != nil {
		return err
	}
	index := slices.IndexFunc(history, func(v store.ParameterVersion) bool { return v.Version == target })
	if index < 0 {
		return store.ErrNotFound
	}
	old := history[index]
	value, err := s.parameters.Value(ctx, entry.Name, target)
	if err != nil {
		return err
	}
	_, err = s.parameters.Update(ctx, store.ParameterUpdate{
		Name: entry.Name, Value: value, Type: old.Type, Tier: entry.SSMTier,
		Description: old.Description, ExpectVersion: expect,
	})
	return err
}

// SaveNote stores the note on an item; an empty note removes it.
func (s *Service) SaveNote(ctx context.Context, subject authz.Subject, kind item.Kind, name, body string) error {
	if _, err := s.entry(ctx, subject, audit.ActionItemNote, kind, name); err != nil {
		return err
	}
	if err := s.authorize(ctx, subject, authz.Edit, audit.ActionItemNote, kind, name); err != nil {
		return err
	}
	body, err := textclean.Clean(body, textclean.Options{MaxLength: 2000, Multiline: true})
	if err != nil {
		return problem.Invalid("Note: %v.", err)
	}
	if err := s.catalog.SaveNote(ctx, kind, name, body, audit.ActorFrom(ctx).Email); err != nil {
		return err
	}
	// Notes are not secret, so their text goes into the audit trail.
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionItemNote, Outcome: audit.Allowed,
		Kind: string(kind), Name: name, Details: map[string]any{"note": body}})
	return nil
}

func cleanDescription(description string) (string, error) {
	cleaned, err := textclean.Clean(description, textclean.Options{MaxLength: 1024})
	if err != nil {
		return "", problem.Invalid("Description: %v.", err)
	}
	return cleaned, nil
}

func validateSSMSettings(ssmType, ssmTier string) error {
	if !slices.Contains(item.SSMTypes, ssmType) {
		return problem.Invalid("Choose a parameter type: %v.", item.SSMTypes)
	}
	if !slices.Contains(item.SSMTiers, ssmTier) {
		return problem.Invalid("Choose a parameter tier: %v.", item.SSMTiers)
	}
	return nil
}
