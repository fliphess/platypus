package web

import (
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
			"ssm_type": {"SecureString"}, "ssm_tier": {"Standard"}, "after": {after},
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
