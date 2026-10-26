// Package authz decides what a user may do with parameters and secrets.
//
// It is deliberately pure: no database, no AWS, no HTTP. Callers load the
// user's rules, build a Subject and ask it. Every permission check in
// platypus, and every disabled button in the UI, goes through Subject.Can,
// so what users see and what is enforced can't drift apart.
package authz

import (
	"fmt"

	"platypus/internal/item"
)

// Permission is something a rule can grant.
type Permission string

const (
	// List lets the user see an item in lists, search and its detail page.
	List Permission = "list"
	// Create lets the user create new items. It never overwrites.
	Create Permission = "create"
	// Edit lets the user change the value, description and note, and roll back.
	Edit Permission = "edit"
	// Reveal lets the user see the current and old values.
	Reveal Permission = "reveal"
)

// AllPermissions lists the permissions in display order.
var AllPermissions = []Permission{List, Create, Edit, Reveal}

// Permissions is a set of granted permissions.
type Permissions struct {
	List   bool
	Create bool
	Edit   bool
	Reveal bool
}

// Has reports whether p is in the set. Edit and Reveal include List: you can't
// work with an item you can't find.
func (ps Permissions) Has(p Permission) bool {
	switch p {
	case List:
		return ps.List || ps.Edit || ps.Reveal
	case Create:
		return ps.Create
	case Edit:
		return ps.Edit
	case Reveal:
		return ps.Reveal
	}
	return false
}

// IsEmpty reports whether nothing is granted.
func (ps Permissions) IsEmpty() bool {
	return ps == Permissions{}
}

// union returns the permissions granted by either set.
func (ps Permissions) union(other Permissions) Permissions {
	return Permissions{
		List:   ps.List || other.List,
		Create: ps.Create || other.Create,
		Edit:   ps.Edit || other.Edit,
		Reveal: ps.Reveal || other.Reveal,
	}
}

// Rule grants permissions on the items of one kind matching a pattern.
type Rule struct {
	Kind        item.Kind
	Pattern     Pattern
	Permissions Permissions
	Source      Source
}

// Source tells where a rule comes from, for the "My permissions" page.
type Source struct {
	Policy string
	// Team is empty when the policy is assigned to the user directly.
	Team string
}

// Subject is a user asking for access: their rules, plus the block switch
// that overrides all of them.
type Subject struct {
	Rules   []Rule
	Blocked bool
}

// Decision is the answer to a permission check. Reason explains a denial in
// words a user understands; it is shown on screen and stored in the audit trail.
type Decision struct {
	Allowed bool
	Reason  string
}

// Can decides whether the subject may use permission p on the named item.
func (s Subject) Can(p Permission, kind item.Kind, name string) Decision {
	if s.Blocked {
		return Decision{Reason: "Platypus is temporarily blocked by an admin."}
	}
	if s.PermissionsOn(kind, name).Has(p) {
		return Decision{Allowed: true}
	}
	return Decision{Reason: fmt.Sprintf(
		"You need the %q permission on this %s. None of your policies grant it; ask an admin.",
		p, kind.Noun())}
}

// PermissionsOn returns everything the rules grant on the named item. It
// ignores the block switch; use Can for decisions.
func (s Subject) PermissionsOn(kind item.Kind, name string) Permissions {
	var granted Permissions
	for _, rule := range s.Rules {
		if rule.Kind == kind && rule.Pattern.Matches(name) {
			granted = granted.union(rule.Permissions)
		}
	}
	return granted
}

// PatternsWith returns the patterns of all rules granting p on items of the
// given kind. Lists and search use it to filter in the database.
func (s Subject) PatternsWith(p Permission, kind item.Kind) []Pattern {
	if s.Blocked {
		return nil
	}
	var patterns []Pattern
	for _, rule := range s.Rules {
		if rule.Kind == kind && rule.Permissions.Has(p) {
			patterns = append(patterns, rule.Pattern)
		}
	}
	return patterns
}

// HasAny reports whether the subject has p on at least one pattern of the
// kind, for example to decide whether to show a "New" button.
func (s Subject) HasAny(p Permission, kind item.Kind) bool {
	return len(s.PatternsWith(p, kind)) > 0
}

// HasAnyAccess reports whether any rule grants anything at all.
func (s Subject) HasAnyAccess() bool {
	for _, rule := range s.Rules {
		if !rule.Permissions.IsEmpty() {
			return true
		}
	}
	return false
}
