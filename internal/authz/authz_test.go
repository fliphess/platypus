package authz

import (
	"strings"
	"testing"

	"platypus/internal/item"
)

func TestParsePattern(t *testing.T) {
	valid := []string{"*", "/apps/*", "/apps/payments/db", "prod/db-*", "name"}
	for _, text := range valid {
		if _, err := ParsePattern(text); err != nil {
			t.Errorf("ParsePattern(%q) error: %v", text, err)
		}
	}

	invalid := map[string]string{
		"":                                      "can't be empty",
		"/apps/*/password":                      "only allowed at the end",
		"**":                                    "only allowed at the end",
		"/a b":                                  "spaces",
		"/a\tb":                                 "spaces",
		strings.Repeat("a", maxPatternLength+1): "at most",
	}
	for text, want := range invalid {
		_, err := ParsePattern(text)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParsePattern(%q) error = %v, want %q", text, err, want)
		}
	}
}

func TestPatternMatches(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*", "/anything/at/all", true},
		{"/apps/*", "/apps/payments/db", true},
		{"/apps/*", "/apps/", true},
		{"/apps/*", "/apps", false},
		{"/apps/*", "/other/apps/x", false},
		{"/apps/payments/db", "/apps/payments/db", true},
		{"/apps/payments/db", "/apps/payments/db2", false},
		{"/apps/payments/db", "/apps/payments", false},
		{"prod/db-*", "prod/db-main", true},
		{"prod/db-*", "prod/dbx", false},
	}
	for _, tt := range tests {
		if got := MustParsePattern(tt.pattern).Matches(tt.name); got != tt.want {
			t.Errorf("%q.Matches(%q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}

func FuzzParsePattern(f *testing.F) {
	for _, seed := range []string{"*", "/a/*", "/a/b", "a*b", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		p, err := ParsePattern(text)
		if err != nil {
			return
		}
		if p.String() != text {
			t.Fatalf("pattern changed: %q -> %q", text, p.String())
		}
		if strings.Contains(p.Literal(), "*") {
			t.Fatalf("literal of %q contains a *", text)
		}
		if !p.Matches(p.Literal()) && p.IsPrefix() {
			t.Fatalf("prefix pattern %q doesn't match its own prefix", text)
		}
	})
}

func rule(kind item.Kind, pattern string, perms Permissions) Rule {
	return Rule{Kind: kind, Pattern: MustParsePattern(pattern), Permissions: perms}
}

func TestCan(t *testing.T) {
	subject := Subject{Rules: []Rule{
		rule(item.KindSSM, "/apps/*", Permissions{List: true}),
		rule(item.KindSSM, "/apps/payments/*", Permissions{Edit: true}),
		rule(item.KindSSM, "/apps/payments/api-key", Permissions{Reveal: true}),
		rule(item.KindSSM, "/sandbox/*", Permissions{Create: true}),
		rule(item.KindSecret, "prod/*", Permissions{Reveal: true}),
	}}

	tests := []struct {
		name       string
		permission Permission
		kind       item.Kind
		item       string
		want       bool
	}{
		{"list through a broad rule", List, item.KindSSM, "/apps/search/url", true},
		{"no edit outside the edit rule", Edit, item.KindSSM, "/apps/search/url", false},
		{"edit through a narrower rule", Edit, item.KindSSM, "/apps/payments/url", true},
		{"reveal on exactly one name", Reveal, item.KindSSM, "/apps/payments/api-key", true},
		{"no reveal next to it", Reveal, item.KindSSM, "/apps/payments/url", false},
		{"create where allowed", Create, item.KindSSM, "/sandbox/new", true},
		{"create doesn't include list", List, item.KindSSM, "/sandbox/new", false},
		{"edit doesn't include create", Create, item.KindSSM, "/apps/payments/new", false},
		{"reveal includes list", List, item.KindSecret, "prod/db", true},
		{"rules don't cross kinds", List, item.KindSecret, "/apps/search/url", false},
		{"nothing matches", List, item.KindSSM, "/other", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := subject.Can(tt.permission, tt.kind, tt.item)
			if got.Allowed != tt.want {
				t.Fatalf("Can(%s, %s, %s) = %+v, want allowed=%v", tt.permission, tt.kind, tt.item, got, tt.want)
			}
			if !got.Allowed && !strings.Contains(got.Reason, string(tt.permission)) {
				t.Errorf("reason %q doesn't name the missing permission", got.Reason)
			}
		})
	}
}

func TestBlockedOverridesEverything(t *testing.T) {
	subject := Subject{
		Rules:   []Rule{rule(item.KindSSM, "*", Permissions{List: true, Create: true, Edit: true, Reveal: true})},
		Blocked: true,
	}
	for _, p := range AllPermissions {
		if d := subject.Can(p, item.KindSSM, "/x"); d.Allowed || !strings.Contains(d.Reason, "blocked") {
			t.Errorf("Can(%s) while blocked = %+v", p, d)
		}
	}
	if len(subject.PatternsWith(List, item.KindSSM)) != 0 {
		t.Error("a blocked subject must not list anything")
	}
}

func TestPatternsWith(t *testing.T) {
	subject := Subject{Rules: []Rule{
		rule(item.KindSSM, "/a/*", Permissions{List: true}),
		rule(item.KindSSM, "/b/*", Permissions{Reveal: true}),
		rule(item.KindSSM, "/c/*", Permissions{Create: true}),
		rule(item.KindSecret, "x/*", Permissions{List: true}),
	}}

	var got []string
	for _, p := range subject.PatternsWith(List, item.KindSSM) {
		got = append(got, p.String())
	}
	if strings.Join(got, ",") != "/a/*,/b/*" {
		t.Errorf("list patterns = %v, want /a/* and /b/* (reveal includes list, create doesn't)", got)
	}
	if !subject.HasAny(Create, item.KindSSM) || subject.HasAny(Create, item.KindSecret) {
		t.Error("HasAny(Create) is wrong")
	}
	if !subject.HasAnyAccess() || (Subject{}).HasAnyAccess() {
		t.Error("HasAnyAccess is wrong")
	}
}
