package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"platypus/internal/access"
	"platypus/internal/authz"
	"platypus/internal/item"
)

// "Save and add another" returns to an empty create form; plain Save returns
// to the item. The choice is carried through the confirmation step.
func TestSaveAndAddAnother(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	h.grant(admin, access.RuleInput{Kind: item.KindSSM, Pattern: "/*",
		Permissions: authz.Permissions{Create: true, List: true}})

	form := func(name, after string) url.Values {
		return url.Values{
			"name": {name}, "value": {"another-value"}, "format": {"text"},
			"description": {"Created by the save-and-add-another test"},
			"ssm_type":    {"SecureString"}, "ssm_tier": {"Standard"}, "after": {after},
		}
	}

	another := h.post("/ssm/new", admin, form("/apps/another", "another"))
	if another.status != http.StatusOK || another.header.Get("HX-Redirect") != "/ssm/new?notice=saved" {
		t.Errorf("save-and-add-another went to %d %q", another.status, another.header.Get("HX-Redirect"))
	}

	view := h.post("/ssm/new", admin, form("/apps/kept", "view"))
	if view.status != http.StatusOK || !strings.Contains(view.header.Get("HX-Redirect"), "/ssm/item?name=") {
		t.Errorf("save went to %d %q", view.status, view.header.Get("HX-Redirect"))
	}
}

// Every item explains itself: create and update refuse a form without a
// description, before anything is written.
func TestDescriptionRequired(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.addParameter("/apps/existing", "value")
	h.elevate(secret)
	h.grant(admin, access.RuleInput{Kind: item.KindSSM, Pattern: "/*",
		Permissions: authz.Permissions{Create: true, List: true, Edit: true}})

	create := url.Values{"name": {"/apps/new"}, "value": {"v"}, "format": {"text"},
		"ssm_type": {"SecureString"}, "ssm_tier": {"Standard"}}
	for _, path := range []string{"/ssm/new/preview", "/ssm/new"} {
		r := h.post(path, admin, create)
		if r.status != http.StatusUnprocessableEntity || !strings.Contains(r.body, "A description is required") {
			t.Errorf("%s without a description = %d %q", path, r.status, r.body)
		}
	}
	if _, err := h.params.Value(context.Background(), "/apps/new", 0); err == nil {
		t.Error("a parameter was created without a description")
	}

	edit := url.Values{"name": {"/apps/existing"}, "value": {"changed"}, "format": {"text"},
		"ssm_type": {"SecureString"}, "ssm_tier": {"Standard"}, "expect_version": {"1"}}
	for _, path := range []string{"/ssm/edit/preview", "/ssm/edit"} {
		r := h.post(path, admin, edit)
		if r.status != http.StatusUnprocessableEntity || !strings.Contains(r.body, "A description is required") {
			t.Errorf("%s without a description = %d %q", path, r.status, r.body)
		}
	}
	value, err := h.params.Value(context.Background(), "/apps/existing", 0)
	if err != nil {
		t.Fatal(err)
	}
	if value.Reveal() != "value" {
		t.Errorf("the value changed without a description: %q", value.Reveal())
	}
}

// A description form is tied to the description it showed: saving it after
// someone else changed the description is a conflict, not a silent overwrite
// (Q02).
func TestDescriptionFingerprint(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	h.addSecret("prod/payments/db", "v1")
	h.grant(admin, access.RuleInput{Kind: item.KindSecret, Pattern: "prod/*",
		Permissions: authz.Permissions{Edit: true, List: true}})

	form := url.Values{"name": {"prod/payments/db"}, "format": {"json"},
		"description": {"Payments database"}, "expect_description": {""},
		"expect_version": {h.secretVersion("prod/payments/db")}}
	first := h.post("/secrets/edit", admin, form)
	h.expect(first, http.StatusOK)

	// The same form again still has the expected version (the value didn't
	// change), but its description is stale.
	stale := h.post("/secrets/edit", admin, form)
	if stale.status != http.StatusConflict {
		t.Fatalf("a stale description form = %d, want 409:\n%s", stale.status, stale.body)
	}
}
