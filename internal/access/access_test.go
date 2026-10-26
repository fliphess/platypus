package access_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"platypus/internal/access"
	"platypus/internal/audit"
	"platypus/internal/authz"
	"platypus/internal/database/dbtest"
	"platypus/internal/db"
	"platypus/internal/item"
	"platypus/internal/problem"
)

func newService(t *testing.T) (*access.Service, *db.Queries) {
	t.Helper()
	pool := dbtest.New(t)
	recorder := audit.NewRecorder(db.New(pool), zap.NewNop())
	return access.NewService(pool, recorder, []string{"example.com"}), db.New(pool)
}

func asAdmin(ctx context.Context) context.Context {
	return audit.WithActor(ctx, audit.Actor{UserID: 1, Email: "admin@example.com"})
}

func TestParseEmail(t *testing.T) {
	domains := []string{"example.com"}
	if got, err := access.ParseEmail("  Jane.Doe@Example.com ", domains); err != nil || got != "jane.doe@example.com" {
		t.Errorf("ParseEmail = %q, %v", got, err)
	}
	for _, bad := range []string{"", "jane", "jane@other.com", "Jane <jane@example.com>", "jane@example.com.evil.org", "a@b@example.com"} {
		if _, err := access.ParseEmail(bad, domains); err == nil {
			t.Errorf("ParseEmail(%q) should fail", bad)
		}
	}
}

func TestUserForLoginCreatesOnce(t *testing.T) {
	svc, q := newService(t)
	ctx := context.Background()

	first, err := svc.UserForLogin(ctx, "new@example.com", "", nil)
	if err != nil {
		t.Fatalf("UserForLogin: %v", err)
	}
	again, err := svc.UserForLogin(ctx, "new@example.com", "", nil)
	if err != nil || again.ID != first.ID {
		t.Fatalf("second login = %+v, %v", again, err)
	}
	if first.IsAdmin || len(first.WebAuthnHandle) != 32 {
		t.Errorf("new user = %+v", first)
	}

	events, _ := q.ListAuditEvents(ctx, db.ListAuditEventsParams{MaxRows: 10})
	if len(events) != 1 || events[0].Action != string(audit.ActionUserCreated) {
		t.Errorf("audit events = %+v, want one user.created", events)
	}
}

// The admin user list is paged: 50 per page, in email order, with the
// total for the pager.
func TestUserListPages(t *testing.T) {
	svc, _ := newService(t)
	ctx := context.Background()
	for i := range 55 {
		if _, err := svc.UserForLogin(ctx, fmt.Sprintf("user%02d@example.com", i), "", nil); err != nil {
			t.Fatal(err)
		}
	}

	first, total, err := svc.UserList(ctx, access.UserFilter{Page: 1})
	if err != nil || total != 55 || len(first) != access.UsersPerPage {
		t.Fatalf("page 1 = %d users, total %d, err %v; want %d and total 55", len(first), total, err, access.UsersPerPage)
	}
	second, _, err := svc.UserList(ctx, access.UserFilter{Page: 2})
	if err != nil || len(second) != 5 {
		t.Fatalf("page 2 = %d users, err %v; want the last 5", len(second), err)
	}
	if second[0].Email != "user50@example.com" {
		t.Errorf("page 2 starts at %s, want user50@example.com", second[0].Email)
	}

	// The search narrows across pages, and the count follows the filter.
	found, total, err := svc.UserList(ctx, access.UserFilter{Page: 1, Search: "user1"})
	if err != nil || total != 10 || len(found) != 10 { // user10..user19
		t.Errorf("search user1 = %d users, total %d, err %v; want 10", len(found), total, err)
	}

	// Pages beyond the end are empty, not an error.
	empty, _, err := svc.UserList(ctx, access.UserFilter{Page: 9})
	if err != nil || len(empty) != 0 {
		t.Errorf("page 9 = %d users, err %v; want empty", len(empty), err)
	}
}

func TestFirstLoginMatchesNoPrecreatedAccounts(t *testing.T) { // Accounts are no longer created ahead of time by typing an address;
	// UserForLogin on first login is the only way in. Twice = one account.
	svc, q := newService(t)
	ctx := context.Background()

	first, err := svc.UserForLogin(ctx, "later@example.com", "", nil)
	if err != nil {
		t.Fatalf("UserForLogin: %v", err)
	}
	again, err := svc.UserForLogin(ctx, "later@example.com", "", nil)
	if err != nil || again.ID != first.ID {
		t.Fatalf("second login = %+v, %v", again, err)
	}
	if count, _ := q.CountUsersWithoutAccess(ctx); count != 1 {
		t.Errorf("users without access = %d, want 1", count)
	}
}

func TestLastAdminCantBeRemoved(t *testing.T) {
	svc, _ := newService(t)
	ctx := asAdmin(context.Background())

	admin, _ := svc.UserForLogin(ctx, "admin@example.com", "", nil)
	if err := svc.SetAdmin(ctx, admin.ID, true); err != nil {
		t.Fatalf("SetAdmin: %v", err)
	}

	for name, change := range map[string]func() error{
		"demote":  func() error { return svc.SetAdmin(ctx, admin.ID, false) },
		"disable": func() error { return svc.SetDisabled(ctx, admin.ID, true) },
	} {
		err := change()
		if p, ok := problem.As(err); !ok || p.Kind != problem.KindConflict {
			t.Errorf("%s the last admin: err = %v, want a conflict", name, err)
		}
	}

	other, _ := svc.UserForLogin(ctx, "other@example.com", "", nil)
	if err := svc.SetAdmin(ctx, other.ID, true); err != nil {
		t.Fatalf("SetAdmin(other): %v", err)
	}
	if err := svc.SetAdmin(ctx, admin.ID, false); err != nil {
		t.Fatalf("demoting with another admin present: %v", err)
	}
}

func TestRulesThroughTeamsAndDirectPolicies(t *testing.T) {
	svc, _ := newService(t)
	ctx := asAdmin(context.Background())

	user, _ := svc.UserForLogin(ctx, "dev@example.com", "", nil)
	team, err := svc.CreateTeam(ctx, access.TeamInput{Name: "Payments"})
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	teamPolicy, err := svc.CreatePolicy(ctx, access.PolicyInput{
		Name: "Payments SSM",
		Rules: []access.RuleInput{
			{Kind: item.KindSSM, Pattern: "/payments/*", Permissions: authz.Permissions{Edit: true}},
		},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	directPolicy, err := svc.CreatePolicy(ctx, access.PolicyInput{
		Name: "One secret",
		Rules: []access.RuleInput{
			{Kind: item.KindSecret, Pattern: "prod/payments/db", Permissions: authz.Permissions{Reveal: true}},
		},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	mustNoErr(t, svc.SetTeamPolicies(ctx, team.ID, []int64{teamPolicy.ID}))
	mustNoErr(t, svc.SetUserTeams(ctx, user.ID, []int64{team.ID}))
	mustNoErr(t, svc.SetUserPolicies(ctx, user.ID, []int64{directPolicy.ID}))

	subject, err := svc.Subject(ctx, user.ID, false)
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}
	if !subject.Can(authz.Edit, item.KindSSM, "/payments/api/url").Allowed {
		t.Error("team policy not applied")
	}
	if !subject.Can(authz.Reveal, item.KindSecret, "prod/payments/db").Allowed {
		t.Error("direct policy not applied")
	}
	if subject.Can(authz.Reveal, item.KindSSM, "/payments/api/url").Allowed {
		t.Error("granted more than the rules say")
	}

	sources := map[string]string{}
	for _, rule := range subject.Rules {
		sources[rule.Source.Policy] = rule.Source.Team
	}
	if sources["Payments SSM"] != "Payments" || sources["One secret"] != "" {
		t.Errorf("rule sources = %v", sources)
	}

	// Leaving the team removes its rules.
	mustNoErr(t, svc.SetUserTeams(ctx, user.ID, nil))
	subject, _ = svc.Subject(ctx, user.ID, false)
	if subject.Can(authz.Edit, item.KindSSM, "/payments/api/url").Allowed {
		t.Error("rules of a team the user left still apply")
	}
}

func TestPolicyValidation(t *testing.T) {
	svc, _ := newService(t)
	ctx := asAdmin(context.Background())

	tests := map[string]access.PolicyInput{
		"no name":         {Name: "  "},
		"bad pattern":     {Name: "x", Rules: []access.RuleInput{{Kind: item.KindSSM, Pattern: "/a/*/b", Permissions: authz.Permissions{List: true}}}},
		"no permissions":  {Name: "x", Rules: []access.RuleInput{{Kind: item.KindSSM, Pattern: "/a/*"}}},
		"unknown kind":    {Name: "x", Rules: []access.RuleInput{{Kind: "s3", Pattern: "*", Permissions: authz.Permissions{List: true}}}},
		"html only names": {Name: "<script></script>"},
	}
	for name, in := range tests {
		if _, err := svc.CreatePolicy(ctx, in); err == nil {
			t.Errorf("%s: CreatePolicy should fail", name)
		}
	}

	created, err := svc.CreatePolicy(ctx, access.PolicyInput{Name: "<b>Clean</b> name"})
	if err != nil || created.Name != "Clean name" {
		t.Errorf("names should be cleaned: %+v, %v", created, err)
	}
	if _, err := svc.CreatePolicy(ctx, access.PolicyInput{Name: "Clean name"}); err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Errorf("duplicate name: err = %v", err)
	}
}

func TestSeedDefaultPoliciesOnce(t *testing.T) {
	_, q := newService(t)
	ctx := context.Background()

	seeded, err := access.SeedDefaultPolicies(ctx, q)
	if err != nil || !seeded {
		t.Fatalf("first seed = %v, %v", seeded, err)
	}
	seeded, err = access.SeedDefaultPolicies(ctx, q)
	if err != nil || seeded {
		t.Fatalf("second seed = %v, %v", seeded, err)
	}
	policies, _ := q.ListPolicies(ctx, "%")
	if len(policies) != len(access.DefaultPolicies) {
		t.Fatalf("%d policies, want %d", len(policies), len(access.DefaultPolicies))
	}
	for _, p := range policies {
		if p.UserCount != 0 || p.TeamCount != 0 {
			t.Errorf("default policy %q must not be assigned", p.Name)
		}
	}
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestTeamsAndMembers(t *testing.T) {
	svc, q := newService(t)
	ctx := asAdmin(context.Background())

	team, err := svc.CreateTeam(ctx, access.TeamInput{Name: "Search", Description: "Search team"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateTeam(ctx, access.TeamInput{Name: "Search"}); err == nil {
		t.Error("a duplicate team name should be refused")
	}

	// Members are picked from people who logged in: there is no adding by
	// typed address (typosquatting).
	user, err := svc.UserForLogin(ctx, "new.person@example.com", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	mustNoErr(t, svc.AddTeamMember(ctx, team.ID, user.ID))
	detail, err := svc.TeamDetail(ctx, team.ID)
	if err != nil || len(detail.Members) != 1 || detail.Members[0].Email != "new.person@example.com" {
		t.Fatalf("members = %+v, %v", detail.Members, err)
	}

	mustNoErr(t, svc.UpdateTeam(ctx, team.ID, access.TeamInput{Name: "Search & Discovery"}))
	mustNoErr(t, svc.RemoveTeamMember(ctx, team.ID, detail.Members[0].ID))
	detail, _ = svc.TeamDetail(ctx, team.ID)
	if detail.Team.Name != "Search & Discovery" || len(detail.Members) != 0 {
		t.Errorf("after update and removal: %+v", detail)
	}

	mustNoErr(t, svc.DeleteTeam(ctx, team.ID))
	if _, err := svc.TeamDetail(ctx, team.ID); err == nil {
		t.Error("a deleted team is still there")
	}

	events, _ := q.ListAuditEvents(ctx, db.ListAuditEventsParams{MaxRows: 100})
	actions := map[string]bool{}
	for _, e := range events {
		actions[e.Action] = true
	}
	for _, want := range []audit.Action{audit.ActionTeamCreated, audit.ActionTeamUpdated, audit.ActionTeamDeleted} {
		if !actions[string(want)] {
			t.Errorf("no %s audit event", want)
		}
	}
}

func TestDisableEndsSessionsAndUnlock(t *testing.T) {
	svc, q := newService(t)
	ctx := asAdmin(context.Background())
	user, _ := svc.UserForLogin(ctx, "dev@example.com", "", nil)

	if err := q.CreateSession(ctx, db.CreateSessionParams{IDHash: []byte("session-hash"), UserID: user.ID, CSRFToken: "x",
		ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	mustNoErr(t, svc.SetDisabled(ctx, user.ID, true))
	if _, err := q.GetSession(ctx, []byte("session-hash")); err == nil {
		t.Error("disabling a user must end their sessions")
	}
	mustNoErr(t, svc.SetDisabled(ctx, user.ID, false))

	if _, err := q.RecordFailedAttempt(ctx, db.RecordFailedAttemptParams{ID: user.ID, MaxAttempts: 1}); err != nil {
		t.Fatal(err)
	}
	locked, _ := svc.User(ctx, user.ID)
	if locked.LockedAt == nil {
		t.Fatal("user should be locked")
	}
	mustNoErr(t, svc.Unlock(ctx, user.ID))
	unlocked, _ := svc.User(ctx, user.ID)
	if unlocked.LockedAt != nil || unlocked.FailedMFAAttempts != 0 {
		t.Errorf("unlock didn't reset the lock: %+v", unlocked)
	}
}

func TestUsersSearchMatchesLiterally(t *testing.T) {
	svc, _ := newService(t)
	ctx := asAdmin(context.Background())
	for _, email := range []string{"a_b@example.com", "axb@example.com"} {
		if _, err := svc.UserForLogin(ctx, email, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	found, err := svc.Users(ctx, "a_b")
	if err != nil || len(found) != 1 || found[0].Email != "a_b@example.com" {
		t.Errorf("search for a_b = %+v, %v (an underscore must not act as a wildcard)", found, err)
	}
}
