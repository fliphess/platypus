package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// Destructive actions say what they cost, and only the dialog's button
// performs them (U17).
func TestDestructiveActionsAskFirst(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)

	page := h.get("/me/security", admin).body
	for _, want := range []string{
		`hx-post="/me/security/totp/remove/preview"`,
		`hx-post="/me/security/recovery-codes/preview"`,
		`hx-target="#dialog-content"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the security page doesn't confirm destructive actions (%q):\n%s", want, page)
		}
	}

	// Recovery codes are replaced, and the preview says the old ones die.
	recovery := h.post("/me/security/recovery-codes/preview", admin, url.Values{})
	h.expect(recovery, http.StatusOK)
	if !strings.Contains(recovery.body, "Create new recovery codes?") ||
		!strings.Contains(recovery.body, `hx-post="/me/security/recovery-codes"`) {
		t.Fatalf("recovery preview = %s", recovery.body)
	}

	// With no recovery codes left, the authenticator is the only factor, and
	// the preview says so.
	adminUser, err := h.q.GetUserByEmail(context.Background(), admin)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.q.DeleteRecoveryCodes(context.Background(), adminUser.ID); err != nil {
		t.Fatal(err)
	}
	totp := h.post("/me/security/totp/remove/preview", admin, url.Values{})
	h.expect(totp, http.StatusOK)
	if !strings.Contains(totp.body, "Remove the authenticator app?") ||
		!strings.Contains(totp.body, "only second factor") {
		t.Fatalf("TOTP preview = %s", totp.body)
	}
	// Opening the dialog changed nothing.
	if !strings.Contains(h.get("/me/security", admin).body, "Remove authenticator app") {
		t.Error("the preview removed the authenticator")
	}
	h.expect(h.post("/me/security/totp/remove", admin, url.Values{}), http.StatusOK)
	if strings.Contains(h.get("/me/security", admin).body, "Remove authenticator app") {
		t.Error("confirming the removal did not remove the authenticator")
	}

	// Disabling an account names the person and locks them out.
	h.get("/me", editor)
	user, err := h.q.GetUserByEmail(context.Background(), editor)
	if err != nil {
		t.Fatal(err)
	}
	userURL := "/admin/users/" + strconv.FormatInt(user.ID, 10)
	disabled := h.post(userURL+"/disabled/preview", admin, url.Values{"disabled": {"true"}})
	h.expect(disabled, http.StatusOK)
	if !strings.Contains(disabled.body, "Disable "+editor+"?") ||
		!strings.Contains(disabled.body, `hx-post="`+userURL+`/disabled"`) {
		t.Fatalf("disable preview = %s", disabled.body)
	}
	if strings.Contains(h.get(userURL, admin).body, `>disabled</span>`) {
		t.Error("the preview disabled the account")
	}

	// Removing someone from a team names the person and the team.
	r := h.post("/admin/teams", admin, url.Values{"name": {"Payments"}})
	h.expect(r, http.StatusOK)
	teamURL := strings.TrimSuffix(r.header.Get("HX-Redirect"), "?notice=created")
	h.expect(h.post(teamURL+"/members", admin, url.Values{"user_id": {strconv.FormatInt(user.ID, 10)}}), http.StatusOK)
	member := h.post(teamURL+"/members/remove/preview", admin,
		url.Values{"user_id": {strconv.FormatInt(user.ID, 10)}})
	h.expect(member, http.StatusOK)
	if !strings.Contains(member.body, "Remove "+editor+" from Payments?") ||
		!strings.Contains(member.body, `hx-post="`+teamURL+`/members/remove"`) {
		t.Fatalf("member preview = %s", member.body)
	}
	h.expect(h.post(teamURL+"/members/remove", admin, url.Values{"user_id": {strconv.FormatInt(user.ID, 10)}}), http.StatusOK)
}
