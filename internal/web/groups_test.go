package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"platypus/internal/access"
	"platypus/internal/auth/authtest"
	"platypus/internal/authz"
	"platypus/internal/db"
	"platypus/internal/item"
)

// Header mode with groups: a team linked to the group takes its members from
// the login, the page says so, and manual membership changes are refused.
func TestGroupLinkedTeamFlow(t *testing.T) {
	h := newHarness(t, withHeaderGroups)
	secret := h.bootstrap()
	h.elevate(secret)

	const editor = "editor@example.com"
	h.setGroups(admin, "admins-group")
	h.setGroups(editor, "payments")

	r := h.post("/admin/policies", admin, url.Values{"name": {"Payments rules"}, "rule_id": {"a"},
		"rule_kind": {"ssm"}, "rule_pattern": {"/payments/*"}, "rule_permission": {"a:list"}})
	h.expect(r, http.StatusOK)
	policyID := strings.TrimPrefix(strings.TrimSuffix(r.header.Get("HX-Redirect"), "?notice=created"), "/admin/policies/")

	r = h.post("/admin/teams", admin, url.Values{"name": {"Payments"}, "idp_group": {"payments"}})
	h.expect(r, http.StatusOK)
	teamURL := strings.TrimSuffix(r.header.Get("HX-Redirect"), "?notice=created")
	h.expect(h.post(teamURL+"/policies", admin, url.Values{"policy_id": {policyID}}), http.StatusOK)

	// The editor's next request puts them in the team: the policy reaches them.
	if !strings.Contains(h.get("/me", editor).body, "Payments rules") {
		t.Error("a group member doesn't see the linked team's policy on My permissions")
	}

	// The team page says where members come from and offers no manual changes.
	team := h.get(teamURL, admin)
	if !strings.Contains(team.body, "Members come from the identity-provider group") {
		t.Errorf("the team page doesn't explain the group link:\n%s", team.body)
	}
	if strings.Contains(team.body, "member-search") || strings.Contains(team.body, "/members/remove") {
		t.Errorf("the linked team page offers manual membership changes:\n%s", team.body)
	}
	if !strings.Contains(team.body, editor) {
		t.Errorf("the group member isn't listed:\n%s", team.body)
	}

	// Manual membership changes are refused — the person has to exist first,
	// picked from the list.
	h.expect(h.get("/me", "nobody@example.com"), http.StatusOK)
	nobody, err := h.q.GetUserByEmail(context.Background(), "nobody@example.com")
	if err != nil {
		t.Fatal(err)
	}
	h.expect(h.post(teamURL+"/members", admin, url.Values{"user_id": {strconv.FormatInt(nobody.ID, 10)}}),
		http.StatusUnprocessableEntity)
	// Posting without picking anyone is refused too.
	h.expect(h.post(teamURL+"/members", admin, url.Values{}), http.StatusUnprocessableEntity)

	// The user page shows the groups and keeps the linked team fixed.
	user, err := h.q.GetUserByEmail(context.Background(), editor)
	if err != nil {
		t.Fatal(err)
	}
	if !userHasGroups(user, "payments") {
		t.Errorf("stored groups = %v", user.IDPGroups)
	}
	userPage := h.get("/admin/users/"+strconv.FormatInt(user.ID, 10), admin)
	if !strings.Contains(userPage.body, `<span class="badge">payments</span>`) {
		t.Errorf("the user page doesn't show the group:\n%s", userPage.body)
	}

	// Losing the group removes the team again: the header stops naming it.
	delete(h.groups, editor)
	if strings.Contains(h.get("/me", editor).body, "Payments rules") {
		t.Error("the editor kept the linked team without its group")
	}

	// Unlinking keeps the members for an admin to remove deliberately.
	h.setGroups(editor, "payments")
	h.get("/me", editor)
	h.expect(h.post(teamURL, admin, url.Values{"name": {"Payments"}}), http.StatusOK)
	if !strings.Contains(h.get(teamURL, admin).body, editor) {
		t.Error("unlinking removed the members")
	}
}

func userHasGroups(user db.User, groups ...string) bool {
	if len(user.IDPGroups) != len(groups) {
		return false
	}
	for i, group := range groups {
		if user.IDPGroups[i] != group {
			return false
		}
	}
	return true
}

// oidc mode: the groups from the ID token reach the linked teams at login.
func TestOIDCGroupsReachTeams(t *testing.T) {
	idp := authtest.New(t)
	h := newHarness(t, withOIDC(idp))
	if err := h.q.SetBootstrapped(context.Background(), true); err != nil {
		t.Fatal(err)
	}

	// A team linked to the group, carrying a policy, set up without the UI.
	policy, err := h.access.CreatePolicy(context.Background(), access.PolicyInput{
		Name:  "Payments rules",
		Rules: []access.RuleInput{{Kind: item.KindSSM, Pattern: "/payments/*", Permissions: authz.Permissions{List: true}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	team, err := h.access.CreateTeam(context.Background(), access.TeamInput{Name: "Payments", IDPGroup: "payments"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.access.SetTeamPolicies(context.Background(), team.ID, []int64{policy.ID}); err != nil {
		t.Fatal(err)
	}

	idp.LogInAs(authtest.User{Email: "jane@example.com", EmailVerified: true, Groups: []string{"payments"}})
	h.oidcLogin(h.client("browser"), "/me")
	me := h.browse(h.client("browser"), http.MethodGet, "/me", nil)
	if !strings.Contains(me.body, "Payments rules") {
		t.Errorf("the group didn't reach the linked team's policy:\n%s", me.body)
	}
	user, err := h.q.GetUserByEmail(context.Background(), "jane@example.com")
	if err != nil || !userHasGroups(user, "payments") {
		t.Errorf("stored groups = %v, %v", user.IDPGroups, err)
	}
}
