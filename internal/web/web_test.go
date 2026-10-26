package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"platypus/internal/access"
	"platypus/internal/authz"
	"platypus/internal/database/dbtest"
	"platypus/internal/item"
)

const (
	admin  = "admin@example.com"
	editor = "editor@example.com"
	nobody = "nobody@example.com"

	paramCanary  = "param-canary-5d1f"
	secretCanary = "secret-canary-8a3b"
)

func TestIdentityIsRequired(t *testing.T) {
	h := newHarness(t)

	h.expect(h.get("/", ""), http.StatusUnauthorized)
	h.expect(h.get("/", "someone@other.org"), http.StatusUnauthorized)
	h.expect(h.get("/", "Jane <jane@example.com>"), http.StatusUnauthorized)

	events, _ := h.q.ListAuditEvents(context.Background(), dbListAll())
	if len(events) != 3 || events[0].Action != "auth.rejected" {
		t.Errorf("rejected requests not audited: %d events", len(events))
	}
}

func TestBootstrapGate(t *testing.T) {
	h := newHarness(t)

	r := h.get("/ssm", admin)
	h.expect(r, http.StatusSeeOther)
	if r.header.Get("Location") != "/bootstrap" {
		t.Fatalf("before setup, pages must lead to /bootstrap, got %q", r.header.Get("Location"))
	}
	if body := h.get("/bootstrap", admin).body; !strings.Contains(body, tokenParam) {
		t.Error("the bootstrap page should say where the token is")
	}

	h.bootstrap()
	r = h.get("/bootstrap", admin)
	if r.status != http.StatusSeeOther || r.header.Get("Location") != "/" {
		t.Errorf("after setup /bootstrap must redirect home, got %d %q", r.status, r.header.Get("Location"))
	}
}

func TestCSRF(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()

	// No token.
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/ssm/note", strings.NewReader("name=x&note=y"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Auth-Request-Email", admin)
	resp, err := h.client(admin).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST without CSRF token = %d, want 403", resp.StatusCode)
	}

	// Right token, but the browser says the request comes from another site.
	req, _ = http.NewRequest(http.MethodPost, h.srv.URL+"/ssm/note", strings.NewReader("name=x&note=y"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Auth-Request-Email", admin)
	req.Header.Set("X-CSRF-Token", h.csrf(admin))
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err = h.client(admin).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site POST = %d, want 403", resp.StatusCode)
	}

	// Another user's token doesn't work either.
	req, _ = http.NewRequest(http.MethodPost, h.srv.URL+"/ssm/note", strings.NewReader("name=x&note=y"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Auth-Request-Email", editor)
	req.Header.Set("X-CSRF-Token", h.csrf(admin))
	resp, err = h.client(editor).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST with another user's token = %d, want 403", resp.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()

	r := h.get("/docs", admin)
	h.expect(r, http.StatusOK)
	for header, want := range map[string]string{
		"Content-Security-Policy": "script-src 'self'",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "same-origin",
		"Cache-Control":           "no-store",
	} {
		if !strings.Contains(r.header.Get(header), want) {
			t.Errorf("%s = %q, want it to contain %q", header, r.header.Get(header), want)
		}
	}
	if strings.Contains(r.header.Get("Content-Security-Policy"), "unsafe") {
		t.Error("the CSP must not allow unsafe-inline or unsafe-eval")
	}

	cookies := h.client(admin).Jar.Cookies(mustURL(t, h.srv.URL))
	if len(cookies) != 1 || cookies[0].Name != "__Host-platypus_session" {
		t.Errorf("session cookie = %+v", cookies)
	}

	static := h.get("/static/style.css", "")
	if static.status != http.StatusOK || !strings.Contains(static.header.Get("Cache-Control"), "max-age") {
		t.Errorf("static files should be served and cached: %d %q", static.status, static.header.Get("Cache-Control"))
	}
}

func TestEveryPageRenders(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.addParameter("/apps/payments/db-url", paramCanary)
	h.addSecret("prod/payments/db", `{"password":"`+secretCanary+`"}`)
	h.grant(editor,
		access.RuleInput{Kind: item.KindSSM, Pattern: "/apps/*", Permissions: authz.Permissions{List: true, Create: true, Edit: true, Reveal: true}},
		access.RuleInput{Kind: item.KindSecret, Pattern: "prod/*", Permissions: authz.Permissions{Edit: true}},
	)

	userPages := []string{
		"/ssm", "/ssm?path=/apps/", "/ssm?q=payments", "/secrets",
		"/ssm/item?name=/apps/payments/db-url", "/secrets/item?name=prod/payments/db",
		"/ssm/new", "/ssm/edit?name=/apps/payments/db-url", "/secrets/edit?name=prod/payments/db",
		"/me", "/docs", "/docs/configuration",
	}
	for _, path := range userPages {
		r := h.get(path, editor)
		if r.status != http.StatusOK {
			t.Errorf("GET %s as editor = %d:\n%s", path, r.status, r.body)
		}
	}

	h.elevate(secret)
	filtered := h.get("/admin/audit?outcome=denied&action=item.reveal", admin)
	if !strings.Contains(filtered.body, `href="/admin/audit.csv?action=item.reveal&amp;outcome=denied"`) {
		t.Errorf("the CSV link doesn't keep the filter:\n%s", filtered.body)
	}
	adminPages := []string{
		"/admin", "/admin/users", "/admin/users/1", "/admin/teams", "/admin/policies",
		"/admin/policies/new", "/admin/policies/1", "/admin/audit", "/admin/audit?outcome=denied",
		"/admin/notes", "/me/security", "/me",
	}
	for _, path := range adminPages {
		r := h.get(path, admin)
		if r.status != http.StatusOK {
			t.Errorf("GET %s as admin = %d:\n%s", path, r.status, r.body)
		}
	}

	nobodyHome := h.get("/ssm", nobody)
	if nobodyHome.status != http.StatusOK || !strings.Contains(nobodyHome.body, "don't have access") {
		t.Errorf("a user without policies should see how to get access:\n%s", nobodyHome.body)
	}
}

func TestPermissionsAreEnforced(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()
	h.addParameter("/apps/payments/db-url", paramCanary)
	h.addParameter("/other/thing", "x")
	h.grant(editor, access.RuleInput{Kind: item.KindSSM, Pattern: "/apps/*", Permissions: authz.Permissions{List: true}})

	listing := h.get("/ssm?q=thing", editor).body
	if strings.Contains(listing, "/other/thing") {
		t.Error("search shows an item outside the user's rules")
	}
	h.expect(h.get("/ssm/item?name=/other/thing", editor), http.StatusNotFound)

	reveal := h.post("/ssm/reveal", editor, url.Values{"name": {"/apps/payments/db-url"}})
	h.expect(reveal, http.StatusForbidden)
	if strings.Contains(reveal.body, paramCanary) {
		t.Fatal("a denied reveal returned the value")
	}
	if !strings.Contains(reveal.body, "reveal") {
		t.Errorf("the denial should name the missing permission: %s", reveal.body)
	}

	// Admin pages: forbidden for users, admin mode first for admins.
	h.expect(h.get("/admin", editor), http.StatusForbidden)
	r := h.get("/admin/users", admin)
	if r.status != http.StatusSeeOther || r.header.Get("Location") != "/admin/elevate" {
		t.Errorf("admin without admin mode: %d %q", r.status, r.header.Get("Location"))
	}
	h.expect(h.post("/admin/block", admin, url.Values{}), http.StatusForbidden)
}

func TestRevealAndEditThroughTheUI(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()
	h.addParameter("/apps/payments/db-url", paramCanary)
	h.grant(editor, access.RuleInput{Kind: item.KindSSM, Pattern: "/apps/*",
		Permissions: authz.Permissions{Create: true, Edit: true, Reveal: true}})

	detail := h.get("/ssm/item?name=/apps/payments/db-url", editor)
	h.expect(detail, http.StatusOK)
	if strings.Contains(detail.body, paramCanary) {
		t.Fatal("the detail page shows the value without a reveal")
	}

	reveal := h.post("/ssm/reveal", editor, url.Values{"name": {"/apps/payments/db-url"}})
	h.expect(reveal, http.StatusOK)
	if !strings.Contains(reveal.body, paramCanary) || reveal.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("reveal = %q, cache %q", reveal.body, reveal.header.Get("Cache-Control"))
	}

	form := url.Values{
		"name": {"/apps/payments/db-url"}, "value": {"line one\r\nline two"}, "format": {"text"},
		"description": {"Database"}, "ssm_type": {"SecureString"}, "ssm_tier": {"Standard"}, "expect_version": {"1"},
	}
	preview := h.post("/ssm/edit/preview", editor, form)
	h.expect(preview, http.StatusOK)
	if !strings.Contains(preview.body, "Continue") || strings.Contains(preview.body, "line one") {
		t.Fatalf("preview must ask to continue and not echo the value:\n%s", preview.body)
	}
	h.expect(h.post("/ssm/edit", editor, form), http.StatusOK)

	value, _ := h.params.Value(context.Background(), "/apps/payments/db-url", 0)
	if value.Reveal() != "line one\nline two" {
		t.Errorf("stored value = %q; textarea CRLF must become LF", value.Reveal())
	}
}

func TestBlockSwitch(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.addParameter("/apps/payments/db-url", paramCanary)
	full := authz.Permissions{List: true, Reveal: true}
	h.grant(editor, access.RuleInput{Kind: item.KindSSM, Pattern: "*", Permissions: full})
	h.grant(admin, access.RuleInput{Kind: item.KindSSM, Pattern: "*", Permissions: full})

	h.elevate(secret)
	h.expect(h.post("/admin/block", admin, url.Values{}), http.StatusOK)

	blocked := h.get("/ssm", editor)
	if blocked.status != http.StatusServiceUnavailable || !strings.Contains(blocked.body, "platform@example.com") {
		t.Errorf("blocked user sees %d:\n%s", blocked.status, blocked.body)
	}

	// Admins keep the admin pages, but can't reveal either.
	h.expect(h.get("/admin", admin), http.StatusOK)
	reveal := h.post("/ssm/reveal", admin, url.Values{"name": {"/apps/payments/db-url"}})
	if reveal.status == http.StatusOK || strings.Contains(reveal.body, paramCanary) {
		t.Fatalf("an admin revealed a value while blocked: %d", reveal.status)
	}

	h.expect(h.post("/admin/unblock", admin, url.Values{}), http.StatusOK)
	h.expect(h.get("/ssm", editor), http.StatusOK)
}

func TestDisabledAndLockedUsers(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.expect(h.get("/me", editor), http.StatusOK)

	h.elevate(secret)
	h.expect(h.post("/admin/users/2/disabled", admin, url.Values{"disabled": {"true"}}), http.StatusOK)
	h.expect(h.get("/me", editor), http.StatusForbidden)
	h.expect(h.post("/admin/users/2/disabled", admin, url.Values{"disabled": {"false"}}), http.StatusOK)
	h.expect(h.get("/me", editor), http.StatusOK)

	// Five wrong codes lock the admin out of platypus entirely.
	for range 5 {
		h.post("/admin/elevate/totp", admin, url.Values{"code": {"000000"}})
	}
	locked := h.get("/me", admin)
	if locked.status != http.StatusForbidden || !strings.Contains(locked.body, "locked") {
		t.Errorf("locked admin sees %d:\n%s", locked.status, locked.body)
	}
}

// Values may only ever appear in a reveal response or the editor of someone
// allowed to reveal: never in logs, the database or other pages.
func TestValuesNeverLeak(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.addParameter("/apps/payments/db-url", paramCanary)
	h.addSecret("prod/payments/db", `{"password":"`+secretCanary+`"}`)
	h.grant(editor,
		access.RuleInput{Kind: item.KindSSM, Pattern: "/apps/*", Permissions: authz.Permissions{Create: true, Edit: true, Reveal: true}},
		access.RuleInput{Kind: item.KindSecret, Pattern: "prod/*", Permissions: authz.Permissions{Edit: true, Reveal: true}},
	)

	h.post("/ssm/reveal", editor, url.Values{"name": {"/apps/payments/db-url"}})
	h.post("/secrets/reveal", editor, url.Values{"name": {"prod/payments/db"}})
	h.get("/secrets/edit?name=prod/payments/db", editor)
	edit := url.Values{"name": {"prod/payments/db"}, "value": {`{"password":"` + secretCanary + `-2"}`}, "format": {"json"}}
	edit.Set("expect_version", h.secretVersion("prod/payments/db"))
	h.post("/secrets/edit/preview", editor, edit)
	h.post("/secrets/edit", editor, edit)
	h.post("/ssm/new", editor, url.Values{"name": {"/apps/new"}, "value": {paramCanary + "-new"}, "format": {"text"},
		"ssm_type": {"SecureString"}, "ssm_tier": {"Standard"}})
	// Too large for SSM: the error must not echo the value.
	tooLarge := h.post("/ssm/new", editor, url.Values{"name": {"/apps/huge"}, "value": {paramCanary + strings.Repeat("x", 5000)},
		"format": {"text"}, "ssm_type": {"SecureString"}, "ssm_tier": {"Standard"}})
	if strings.Contains(tooLarge.body, paramCanary) {
		t.Error("an error message echoes the value")
	}

	h.elevate(secret)
	auditPage := h.get("/admin/audit", admin).body
	csv := h.get("/admin/audit.csv", admin).body
	detail := h.get("/ssm/item?name=/apps/payments/db-url", editor).body

	places := map[string]string{
		"logs":        h.logs.String(),
		"database":    dbtest.TableDump(t, h.pool),
		"audit page":  auditPage,
		"audit CSV":   csv,
		"detail page": detail,
	}
	for place, content := range places {
		for _, canary := range []string{paramCanary, secretCanary} {
			if strings.Contains(content, canary) {
				t.Errorf("a value leaked into the %s", place)
			}
		}
	}
}

func (h *harness) secretVersion(name string) string {
	h.t.Helper()
	entry, found, err := h.catalog.Get(context.Background(), item.KindSecret, name)
	if err != nil || !found {
		h.t.Fatalf("secret %s not in the catalog", name)
	}
	return entry.Version()
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAdminPages(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)

	// Teams: create, add a member picked from the list, assign a policy, rename, delete.
	r := h.post("/admin/teams", admin, url.Values{"name": {"Payments"}, "description": {"Payments team"}})
	h.expect(r, http.StatusOK)
	teamURL := strings.TrimSuffix(r.header.Get("HX-Redirect"), "?notice=created")
	// The member has an account from logging in; the picker adds by user id.
	h.expect(h.get("/me", "new@example.com"), http.StatusOK)
	newUser, err := h.q.GetUserByEmail(context.Background(), "new@example.com")
	if err != nil {
		t.Fatal(err)
	}
	h.expect(h.post(teamURL+"/members", admin, url.Values{"user_id": {strconv.FormatInt(newUser.ID, 10)}}), http.StatusOK)
	h.expect(h.post(teamURL+"/policies", admin, url.Values{"policy_id": {"1"}}), http.StatusOK)
	h.expect(h.post(teamURL, admin, url.Values{"name": {"Payments & Billing"}}), http.StatusOK)
	team := h.get(teamURL, admin)
	if !strings.Contains(team.body, "new@example.com") || !strings.Contains(team.body, "Payments &amp; Billing") {
		t.Errorf("team page after changes:\n%s", team.body)
	}

	confirm := h.post(teamURL+"/delete/preview", admin, url.Values{})
	if confirm.status != http.StatusOK || !strings.Contains(confirm.body, "Its members (1 person) lose") {
		t.Errorf("deleting a team should ask first: %d %s", confirm.status, confirm.body)
	}

	// The new member got the team's policy.
	if !strings.Contains(h.get("/me", "new@example.com").body, "Read-only all") {
		t.Error("the member doesn't see the team's policy on My permissions")
	}

	// Policies: create, update, delete.
	r = h.post("/admin/policies", admin, url.Values{"name": {"Sandbox"}, "rule_id": {"a"}, "rule_kind": {"ssm"},
		"rule_pattern": {"/sandbox/*"}, "rule_permission": {"a:create"}})
	h.expect(r, http.StatusOK)
	policyURL := strings.TrimSuffix(r.header.Get("HX-Redirect"), "?notice=created")
	h.expect(h.post(policyURL, admin, url.Values{"name": {"Sandbox editors"}, "rule_id": {"a"}, "rule_kind": {"ssm"},
		"rule_pattern": {"/sandbox/*"}, "rule_permission": {"a:create", "a:edit"}}), http.StatusOK)
	if !strings.Contains(h.get(policyURL, admin).body, "Sandbox editors") {
		t.Error("policy update not shown")
	}
	bad := h.post("/admin/policies", admin, url.Values{"name": {"Broken"}, "rule_id": {"a"}, "rule_kind": {"ssm"},
		"rule_pattern": {"/a/*/b"}, "rule_permission": {"a:list"}})
	if bad.status != http.StatusUnprocessableEntity || !strings.Contains(bad.body, "only allowed at the end") {
		t.Errorf("a bad pattern should be explained: %d %s", bad.status, bad.body)
	}
	confirm = h.post(policyURL+"/delete/preview", admin, url.Values{})
	if confirm.status != http.StatusOK || !strings.Contains(confirm.body, "Delete policy Sandbox editors?") {
		t.Errorf("deleting a policy should ask first: %d %s", confirm.status, confirm.body)
	}
	h.expect(h.post(policyURL+"/delete", admin, url.Values{}), http.StatusOK)

	// Users: an account made by logging in, made admin, unlocked.
	h.expect(h.get("/me", "later@example.com"), http.StatusOK)
	later, err := h.q.GetUserByEmail(context.Background(), "later@example.com")
	if err != nil {
		t.Fatal(err)
	}
	userURL := "/admin/users/" + strconv.FormatInt(later.ID, 10)
	h.expect(h.post(userURL+"/admin", admin, url.Values{"admin": {"true"}}), http.StatusOK)
	h.expect(h.post(userURL+"/unlock", admin, url.Values{}), http.StatusOK)
	if !strings.Contains(h.get("/admin/users?q=later", admin).body, "later@example.com") {
		t.Error("user search doesn't find the new user")
	}

	// Sync request, audit filter and prune, leaving admin mode.
	h.expect(h.post("/admin/sync", admin, url.Values{"recheck_access": {"on"}}), http.StatusOK)
	h.expect(h.post("/admin/audit/prune/preview", admin, url.Values{}), http.StatusOK)
	h.expect(h.post("/admin/audit/prune", admin, url.Values{}), http.StatusOK)
	csv := h.get("/admin/audit.csv", admin)
	if csv.status != http.StatusOK || !strings.HasPrefix(csv.body, "id,occurred_at") {
		t.Errorf("CSV export = %d %q", csv.status, csv.body[:min(len(csv.body), 80)])
	}
	h.expect(h.post("/admin/leave", admin, url.Values{}), http.StatusOK)
	r = h.get("/admin", admin)
	if r.status != http.StatusSeeOther {
		t.Errorf("after leaving admin mode /admin = %d", r.status)
	}
}

func TestLoadCurrentValue(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()
	h.addSecret("prod/payments/db", `{"password":"`+secretCanary+`"}`)
	h.grant(editor, access.RuleInput{Kind: item.KindSecret, Pattern: "prod/*", Permissions: authz.Permissions{Edit: true, Reveal: true}})

	form := h.get("/secrets/edit?name=prod/payments/db", editor)
	h.expect(form, http.StatusOK)
	if strings.Contains(form.body, secretCanary) || !strings.Contains(form.body, "Load current value") {
		t.Fatal("the edit page must not show the value until asked, and offer to load it")
	}

	loaded := h.post("/secrets/edit/value", editor, url.Values{"name": {"prod/payments/db"}})
	h.expect(loaded, http.StatusOK)
	if !strings.Contains(loaded.body, secretCanary) || !strings.Contains(loaded.body, `value="json" checked`) {
		t.Fatalf("loaded editor = %s", loaded.body)
	}

	// A value that is valid JSON but not an object or array (a number, a
	// bare word) stays in text mode: people save strings as strings.
	h.addSecret("prod/payments/pin", "123456")
	pin := h.post("/secrets/edit/value", editor, url.Values{"name": {"prod/payments/pin"}})
	h.expect(pin, http.StatusOK)
	if !strings.Contains(pin.body, `value="text" checked`) || strings.Contains(pin.body, `value="json" checked`) {
		t.Fatalf("a numeric secret must edit as text, not JSON:\n%s", pin.body)
	}
	events, _ := h.q.ListAuditEvents(context.Background(), dbListAll())
	if events[0].Action != "item.reveal" || !strings.Contains(string(events[0].Details), "edit") {
		t.Errorf("loading the value must be audited as a reveal, got %s %s", events[0].Action, events[0].Details)
	}

	h.grant(editor, access.RuleInput{Kind: item.KindSecret, Pattern: "prod/*", Permissions: authz.Permissions{Edit: true}})
	if form := h.get("/secrets/edit?name=prod/payments/db", editor); strings.Contains(form.body, "Load current value") {
		t.Error("users who may not reveal shouldn't get the load button")
	}
	h.expect(h.post("/secrets/edit/value", editor, url.Values{"name": {"prod/payments/db"}}), http.StatusForbidden)
}

func TestProfileAndFrontPage(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()
	h.addParameter("/apps/a", "x")
	h.addParameter("/apps/b", "x")
	h.grant(editor, access.RuleInput{Kind: item.KindSSM, Pattern: "/apps/*", Permissions: authz.Permissions{List: true}})

	home := h.get("/", editor)
	h.expect(home, http.StatusOK)
	if !strings.Contains(home.body, `<span class="stat-number">2</span>`) || strings.Contains(home.body, "/apps/a") {
		t.Errorf("the front page should count what the user can see, without listing it:\n%s", home.body)
	}

	h.expect(h.post("/me/profile", editor, url.Values{"display_name": {"Edith <b>Editor</b>"}, "department": {"Payments"}}), http.StatusOK)
	page := h.get("/me/profile", editor)
	if !strings.Contains(page.body, `value="Edith Editor"`) || !strings.Contains(page.body, ">Edith Editor</a>") {
		t.Errorf("the name should be cleaned, saved and shown in the header:\n%s", page.body)
	}
	if !strings.Contains(h.get("/", editor).body, "Hello, Edith Editor") {
		t.Error("the front page should greet the user by name")
	}
}

func TestHomePageStatStrip(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	// The stats only exist for someone with access; the admin starts without.
	h.grant(admin, access.RuleInput{Kind: item.KindSSM, Pattern: "/*", Permissions: authz.Permissions{List: true}})

	page := h.get("/", admin).body
	for _, want := range []string{`class="stat-number"`, `class="stat-label"`} {
		if !strings.Contains(page, want) {
			t.Errorf("home page missing %s:\n%s", want, page)
		}
	}
	if strings.Contains(page, `class="tile`) {
		t.Error("the tile mosaic is still there")
	}
	if strings.Contains(page, "home-links") {
		t.Error("the stray links row is back on the home page")
	}
	// The admin status chip in the header is the way into the admin area.
	if !strings.Contains(page, `class="chip"`) {
		t.Error("the admin chip is missing from the header")
	}
	// Someone without access sees the quiet no-access hint instead of zeros.
	h.get("/me", nobody)
	if body := h.get("/", nobody).body; !strings.Contains(body, "You don't have access") || strings.Contains(body, "stat-number") {
		t.Errorf("no-access home:\n%s", body)
	}
}

func TestTeamMemberPicker(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	h.get("/me", editor) // editor logs in once
	h.post("/me/profile", editor, url.Values{"display_name": {"Edith Editor"}})
	h.get("/me", nobody) // a second person who may join

	r := h.post("/admin/teams", admin, url.Values{"name": {"Payments"}})
	teamURL := strings.TrimSuffix(r.header.Get("HX-Redirect"), "?notice=created")

	// The list shows without typing: everyone with an account, nobody else.
	eager := h.get(teamURL+"/candidates", admin)
	for _, want := range []string{"Edith Editor", nobody} {
		if !strings.Contains(eager.body, want) {
			t.Fatalf("the list should show %s straight away: %s", want, eager.body)
		}
	}
	if strings.Contains(eager.body, `name="email"`) {
		t.Errorf("picking must not offer a free-text email field: %s", eager.body)
	}

	// Typing narrows by name or by the username part of the address.
	byName := h.get(teamURL+"/candidates?q=edith", admin)
	if !strings.Contains(byName.body, "Edith Editor") || strings.Contains(byName.body, nobody) {
		t.Fatalf("search by name = %s", byName.body)
	}
	byUser := h.get(teamURL+"/candidates?q=editor@", admin)
	if !strings.Contains(byUser.body, "Edith Editor") {
		t.Fatalf("search by username = %s", byUser.body)
	}

	// An address nobody logged in with stays unknown: no account is created
	// from a typed address.
	newcomer := h.get(teamURL+"/candidates?q=newcomer@example.com", admin)
	if strings.Contains(newcomer.body, "hasn't logged in") || strings.Contains(newcomer.body, `name="email"`) {
		t.Fatalf("search for a new email = %s", newcomer.body)
	}
	h.expect(h.post(teamURL+"/members", admin, url.Values{"email": {"newcomer@example.com"}}),
		http.StatusUnprocessableEntity)

	userID := regexp.MustCompile(`name="user_id" value="(\d+)"`).FindStringSubmatch(byName.body)[1]
	h.expect(h.post(teamURL+"/members", admin, url.Values{"user_id": {userID}}), http.StatusOK)
	team := h.get(teamURL, admin).body
	if !strings.Contains(team, "Edith Editor") {
		t.Errorf("team members after adding:\n%s", team)
	}
	if again := h.get(teamURL+"/candidates?q=edith", admin); strings.Contains(again.body, `name="user_id"`) {
		t.Error("members already in the team shouldn't be offered again")
	}
}

func TestAdminOverviewHasNoLinkOnlyCards(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)

	overview := h.get("/admin", admin).body
	for _, clutter := range []string{"<h2>People</h2>", "<h2>Notes</h2>", "See them"} {
		if strings.Contains(overview, clutter) {
			t.Errorf("overview still has a link-only card (%s):\n%s", clutter, overview)
		}
	}
	// Orphaned notes are their own view, reachable from the section links.
	if !strings.Contains(overview, `href="/admin/notes"`) {
		t.Error("the orphaned notes view is not reachable from the admin sections")
	}
	for _, want := range []string{"Block all access", "Sync with AWS"} {
		if !strings.Contains(overview, want) {
			t.Errorf("overview lost an acting card: %s", want)
		}
	}
}

func TestPasskeysCanBeSwitchedOff(t *testing.T) {
	h := newHarness(t, withoutPasskeys)
	secret := h.bootstrap()
	h.elevate(secret)

	if strings.Contains(h.get("/me/security", admin).body, "Add a passkey") {
		t.Error("the security page offers passkeys while they are off")
	}
	h.expect(h.post("/me/security/passkeys/begin", admin, url.Values{}), http.StatusNotFound)
}

// An admin who removed their authenticator but kept recovery codes still has
// a factor: a stolen session alone must not add a new authenticator.
func TestRecoveryCodesCountAsAFactor(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	h.expect(h.post("/me/security/totp/remove", admin, url.Values{}), http.StatusOK)
	h.expect(h.post("/admin/leave", admin, url.Values{}), http.StatusOK)

	h.expect(h.post("/me/security/totp", admin, url.Values{}), http.StatusForbidden)
	h.expect(h.post("/me/security/passkeys/begin", admin, url.Values{}), http.StatusForbidden)
	if strings.Contains(h.get("/me/security", admin).body, "Set up an authenticator app") {
		t.Error("the security page offers to add an authenticator without admin mode")
	}
}

// Every admin route refuses non-admins, and admins outside admin mode.
func TestEveryAdminRouteNeedsAdminMode(t *testing.T) {
	h := newHarness(t)
	h.bootstrap()
	h.expect(h.post("/admin/leave", admin, url.Values{}), http.StatusOK)
	h.get("/", editor)

	for _, route := range h.server.adminRoutes() {
		method, path, _ := strings.Cut(route.pattern, " ")
		path = strings.ReplaceAll(path, "{id}", "1")
		if r := h.do(method, path, editor, url.Values{}, false); r.status != http.StatusForbidden {
			t.Errorf("%s as editor = %d, want 403", route.pattern, r.status)
		}
		want := http.StatusForbidden
		if method == http.MethodGet {
			want = http.StatusSeeOther
		}
		if r := h.do(method, path, admin, url.Values{}, false); r.status != want {
			t.Errorf("%s as admin outside admin mode = %d, want %d", route.pattern, r.status, want)
		}
	}
}

func TestUnderAdmin(t *testing.T) {
	for pattern, want := range map[string]bool{
		"GET /admin":           true,
		"POST /admin/users":    true,
		"GET /admin/audit.csv": true,
		"GET /administrator":   false,
		"GET /me":              false,
	} {
		if got := underAdmin(pattern); got != want {
			t.Errorf("underAdmin(%q) = %v, want %v", pattern, got, want)
		}
	}
}

// The audit trail: filters apply without a button, dates are date pickers,
// people are picked from the known accounts, and a username links to their
// trail.
func TestAuditTrailFilters(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	h.get("/me", editor)
	// A peek at an item the editor can't list: refused, and audited as denied.
	h.expect(h.get("/ssm/item?name=/apps/a", editor), http.StatusNotFound)

	page := h.get("/admin/audit", admin).body
	for _, want := range []string{
		`hx-get="/admin/audit"`,                    // filters apply on change
		`type="date"`,                              // from/until are date pickers
		`<select id="actor" name="actor">`,         // the user filter is a picker, no free text
		`<option value="` + editor + `">` + editor, // over the known accounts
		`href="/admin/audit?actor=`,                // usernames link to their trail
	} {
		if !strings.Contains(page, want) {
			t.Errorf("audit page missing %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, ">Filter<") {
		t.Error("the audit trail still has a Filter button")
	}

	// Following a username link filters to that user's events.
	filtered := h.get("/admin/audit?actor="+editor, admin).body
	if !strings.Contains(filtered, `value="`+editor+`"`) {
		t.Error("the actor filter does not echo the chosen user")
	}

	// The htmx request returns just the results, so filters swap in place.
	results := h.do(http.MethodGet, "/admin/audit?outcome=denied", admin, nil, true)
	if results.status != http.StatusOK || !strings.Contains(results.body, `class="event"`) {
		t.Errorf("fragment response: %d %.200s", results.status, results.body)
	}
	if strings.Contains(results.body, "<html") {
		t.Error("the htmx response is a full page, not the results fragment")
	}
}

// Admins see who logged in without any access, to give them some or shut
// them out.
func TestUsersWithoutAccess(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	h.grant(editor, access.RuleInput{Kind: item.KindSSM, Pattern: "/apps/*", Permissions: authz.Permissions{List: true}})
	h.get("/", nobody)

	// The overview doesn't nag about them (no attention cards); the users
	// view is where that state lives.
	if overview := h.get("/admin", admin); strings.Contains(overview.body, "without any access") {
		t.Errorf("the overview nags about users without access:\n%s", overview.body)
	}
	without := h.get("/admin/users?access=none", admin)
	if !strings.Contains(without.body, nobody) || strings.Contains(without.body, editor) {
		t.Errorf("users without access should list nobody, not editor:\n%s", without.body)
	}
	all := h.get("/admin/users", admin)
	if !strings.Contains(all.body, "1 policy") || !strings.Contains(all.body, "no access") {
		t.Errorf("the user list should show each user's access:\n%s", all.body)
	}
}
