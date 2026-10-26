package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"platypus/internal/access"
	"platypus/internal/authz"
	"platypus/internal/db"
	"platypus/internal/item"
)

// The admin user list: the without-access filter, and disabling people
// straight from the list, which is how an admin blocks whoever shouldn't
// use platypus at all.
func TestAdminUsersList(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)

	// Three people: one with access through a policy, one waiting, one to
	// block. The admin (first user) comes with the harness.
	policy, err := h.access.CreatePolicy(context.Background(), access.PolicyInput{
		Name:  "Sandbox read",
		Rules: []access.RuleInput{{Kind: item.KindSSM, Pattern: "/sandbox/*", Permissions: authz.Permissions{List: true}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	withAccess, err := h.access.UserForLogin(context.Background(), "reader@example.com", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.access.SetUserPolicies(context.Background(), withAccess.ID, []int64{policy.ID}); err != nil {
		t.Fatal(err)
	}
	pending, err := h.access.UserForLogin(context.Background(), "pending@example.com", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := h.access.UserForLogin(context.Background(), "stranger@example.com", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	all := h.get("/admin/users", admin)
	for _, email := range []string{admin, "reader@example.com", "pending@example.com", "stranger@example.com"} {
		if !strings.Contains(all.body, email) {
			t.Errorf("all users is missing %s:\n%s", email, all.body)
		}
	}
	if !strings.Contains(all.body, "1 policy") {
		t.Error("the reader's policy count is missing")
	}

	// The without-access tab shows only people no policy reaches.
	none := h.get("/admin/users?access=none", admin)
	if !strings.Contains(none.body, "pending@example.com") || !strings.Contains(none.body, "stranger@example.com") {
		t.Errorf("without access should list the waiting and the strangers:\n%s", none.body)
	}
	if strings.Contains(none.body, "reader@example.com") {
		t.Error("the reader has access and shouldn't be in the without-access list")
	}

	// The search narrows, either tab.
	if got := h.get("/admin/users?access=none&q=stranger", admin); !strings.Contains(got.body, "stranger@example.com") || strings.Contains(got.body, "pending@example.com") {
		t.Errorf("search within the tab should narrow:\n%s", got.body)
	}

	// Blocking from the list stays on the list: the action returns to where
	// the form came from, and the next visit of the blocked user is refused.
	block := h.post("/admin/users/"+strconv.FormatInt(stranger.ID, 10)+"/disabled", admin,
		url.Values{"disabled": {"true"}, "return": {"/admin/users?access=none"}})
	if block.status != http.StatusOK || block.header.Get("HX-Redirect") != "/admin/users?access=none&notice=saved" {
		t.Fatalf("disable from the list: %d %q", block.status, block.header.Get("HX-Redirect"))
	}
	after := h.get("/admin/users?access=none", admin)
	if !strings.Contains(after.body, `<span class="badge danger">disabled</span>`) {
		t.Errorf("the stranger should show as disabled:\n%s", after.body)
	}
	if r := h.get("/ssm", "stranger@example.com"); r.status != http.StatusForbidden {
		t.Errorf("a blocked user's request: %d, want the disabled page", r.status)
	}

	// Enabling works the same way.
	enable := h.post("/admin/users/"+strconv.FormatInt(stranger.ID, 10)+"/disabled", admin,
		url.Values{"disabled": {"false"}, "return": {"/admin/users"}})
	if enable.status != http.StatusOK || !strings.Contains(h.get("/ssm", "stranger@example.com").body, "You don't have access") {
		t.Errorf("enabling didn't let the user back in: %d", enable.status)
	}

	// An unknown return address is refused: only local paths back into
	// platypus, never a redirect elsewhere.
	hijack := h.post("/admin/users/"+strconv.FormatInt(pending.ID, 10)+"/disabled", admin,
		url.Values{"disabled": {"true"}, "return": {"https://evil.example.com"}})
	if want := "/admin/users/" + strconv.FormatInt(pending.ID, 10) + "?notice=saved"; hijack.status != http.StatusOK ||
		hijack.header.Get("HX-Redirect") != want {
		t.Errorf("a foreign return address: %d %q, want %q", hijack.status, hijack.header.Get("HX-Redirect"), want)
	}
}

// The user list paginates and searches live: the htmx request returns just
// the table, and the pager carries the search and the view.
func TestUsersPagePagination(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	for i := range 52 {
		h.expect(h.get("/me", fmt.Sprintf("person%02d@example.com", i)), http.StatusOK)
	}

	page := h.get("/admin/users", admin).body
	if !strings.Contains(page, "Page 1 of 2") || !strings.Contains(page, "53 users") {
		t.Errorf("the pager is missing or wrong:\n%.600s", page)
	}

	next := h.get("/admin/users?page=2", admin).body
	if !strings.Contains(next, "person51@example.com") || strings.Contains(next, "person00@example.com") {
		t.Errorf("page 2 should hold the tail of the list:\n%.600s", next)
	}

	// Live search: htmx returns only the table fragment.
	results := h.do(http.MethodGet, "/admin/users?q=person5", admin, nil, true)
	if results.status != http.StatusOK || !strings.Contains(results.body, "person50@example.com") ||
		strings.Contains(results.body, "<html") {
		t.Errorf("live search fragment: %d %.300s", results.status, results.body)
	}
}

// Creating an account ahead of the first login is its own page; the list
// itself stays a list.
func TestAddUserPage(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)

	page := h.get("/admin/users", admin).body
	if strings.Contains(page, `name="email"`) {
		t.Error("the users list still carries a create form")
	}
	if !strings.Contains(page, `href="/admin/users/new"`) {
		t.Error("the users list has no New user action")
	}

	form := h.get("/admin/users/new", admin)
	h.expect(form, http.StatusOK)
	if !strings.Contains(form.body, `name="email"`) {
		t.Error("the new-user page has no email field")
	}

	h.expect(h.post("/admin/users", admin, url.Values{"email": {"Ahead.Of.Login@example.com"}}), http.StatusOK)
	list := h.get("/admin/users?q=ahead.of.login", admin).body
	if !strings.Contains(list, "not logged in yet") {
		t.Errorf("the pre-registered account should show as not logged in yet:\n%s", list)
	}

	// Teams work the same way: the list lists, the form has its own page.
	teams := h.get("/admin/teams", admin).body
	if strings.Contains(teams, "Create a team") {
		t.Error("the teams list still contains the create form")
	}
	h.expect(h.get("/admin/teams/new", admin), http.StatusOK)
}

// Listing with a search names what was listed in the audit trail, so
// "item.list" rows are not anonymous.
func TestListAuditNamesTheList(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	h.grant(admin, access.RuleInput{Kind: item.KindSSM, Pattern: "/*", Permissions: authz.Permissions{List: true}})

	h.get("/ssm?q=payments", admin)

	events, err := h.q.ListAuditEvents(context.Background(), db.ListAuditEventsParams{MaxRows: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == "item.list" {
			if event.ResourceName != "/ssm?q=payments" {
				t.Errorf("list event names %q, want /ssm?q=payments", event.ResourceName)
			}
			return
		}
	}
	t.Error("no item.list event was recorded")
}
