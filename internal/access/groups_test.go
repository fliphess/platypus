package access_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"platypus/internal/access"
	"platypus/internal/audit"
	"platypus/internal/db"
	"platypus/internal/problem"
)

func memberEmails(t *testing.T, q *db.Queries, teamID int64) []string {
	t.Helper()
	members, err := q.ListTeamMembers(context.Background(), teamID)
	if err != nil {
		t.Fatal(err)
	}
	emails := make([]string, len(members))
	for i, member := range members {
		emails[i] = member.Email
	}
	return emails
}

func TestGroupLinkedTeamsFollowTheGroups(t *testing.T) {
	svc, q := newService(t)
	ctx := asAdmin(context.Background())

	linked, err := svc.CreateTeam(ctx, access.TeamInput{Name: "Payments", IDPGroup: "payments"})
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	manual, err := svc.CreateTeam(ctx, access.TeamInput{Name: "Onboarding"})
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}

	// A login that reports the group puts the user in the linked team.
	user, err := svc.UserForLogin(ctx, "dev@example.com", "", []string{"other", "payments"})
	if err != nil {
		t.Fatalf("UserForLogin: %v", err)
	}
	if !slices.Contains(memberEmails(t, q, linked.ID), "dev@example.com") {
		t.Error("the user is not in the team linked to their group")
	}
	stored, err := q.GetUser(context.Background(), user.ID)
	if err != nil || !slices.Equal(stored.IDPGroups, []string{"other", "payments"}) {
		t.Errorf("stored groups = %v, %v", stored.IDPGroups, err)
	}

	// A manual team is untouched by the sync.
	if err := svc.AddTeamMember(ctx, manual.ID, user.ID); err != nil {
		t.Fatalf("AddTeamMember: %v", err)
	}

	// A later login without the group removes only the linked membership.
	if _, err := svc.UserForLogin(ctx, "dev@example.com", "", []string{}); err != nil {
		t.Fatalf("UserForLogin without groups: %v", err)
	}
	if slices.Contains(memberEmails(t, q, linked.ID), "dev@example.com") {
		t.Error("the user kept the linked team without its group")
	}
	if !slices.Contains(memberEmails(t, q, manual.ID), "dev@example.com") {
		t.Error("the sync touched a team without a group link")
	}

	events, err := q.ListAuditEvents(context.Background(), db.ListAuditEventsParams{MaxRows: 50})
	if err != nil {
		t.Fatal(err)
	}
	joined, left := false, false
	for _, event := range events {
		if event.Action == string(audit.ActionUserTeams) && strings.Contains(string(event.Details), "group sync") {
			if strings.Contains(string(event.Details), `"dev@example.com"`) {
				if strings.Contains(string(event.Details), "Payments") {
					joined = true
				}
				if strings.Contains(string(event.Details), "removed_from") {
					left = true
				}
			}
		}
	}
	if !joined || !left {
		t.Errorf("group sync audit events: joined %v, left %v", joined, left)
	}
}

func TestGroupMappingOffChangesNothing(t *testing.T) {
	svc, q := newService(t)
	ctx := asAdmin(context.Background())

	// The members a team already has stay when the link is made; a login
	// that doesn't read groups (nil) leaves both alone.
	team, err := svc.CreateTeam(ctx, access.TeamInput{Name: "Payments"})
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	user, err := svc.UserForLogin(ctx, "dev@example.com", "", nil)
	if err != nil {
		t.Fatalf("UserForLogin: %v", err)
	}
	if err := svc.AddTeamMember(ctx, team.ID, user.ID); err != nil {
		t.Fatalf("AddTeamMember: %v", err)
	}
	if err := svc.UpdateTeam(ctx, team.ID, access.TeamInput{Name: "Payments", IDPGroup: "payments"}); err != nil {
		t.Fatalf("UpdateTeam: %v", err)
	}

	if _, err := svc.UserForLogin(ctx, "dev@example.com", "", nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(memberEmails(t, q, team.ID), "dev@example.com") {
		t.Error("a login without group mapping removed a member")
	}

	// The same login with the mapping on (empty groups) does remove them.
	if _, err := svc.UserForLogin(ctx, "dev@example.com", "", []string{}); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(memberEmails(t, q, team.ID), "dev@example.com") {
		t.Error("a login reporting no groups kept the linked team")
	}
}

func TestLinkedTeamsAreReadOnly(t *testing.T) {
	svc, q := newService(t)
	ctx := asAdmin(context.Background())

	linked, err := svc.CreateTeam(ctx, access.TeamInput{Name: "Payments", IDPGroup: "payments"})
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if _, err := svc.CreateTeam(ctx, access.TeamInput{Name: "Other", IDPGroup: "payments"}); err == nil {
		t.Error("two teams may link to the same group")
	} else if p, ok := problem.As(err); !ok || p.Kind != problem.KindConflict {
		t.Errorf("second link: %v", err)
	}

	user, err := svc.UserForLogin(ctx, "dev@example.com", "", []string{"payments"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := svc.UserForLogin(ctx, "other@example.com", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	manual, err := svc.CreateTeam(ctx, access.TeamInput{Name: "Onboarding"})
	if err != nil {
		t.Fatal(err)
	}

	for name, change := range map[string]func() error{
		"add member":    func() error { return svc.AddTeamMember(ctx, linked.ID, other.ID) },
		"remove member": func() error { return svc.RemoveTeamMember(ctx, linked.ID, user.ID) },
		"set user teams": func() error {
			return svc.SetUserTeams(ctx, user.ID, []int64{linked.ID, manual.ID})
		},
	} {
		err := change()
		if p, ok := problem.As(err); !ok || p.Kind != problem.KindInvalid {
			t.Errorf("%s on a linked team: err = %v, want an explained refusal", name, err)
		}
	}

	// SetUserTeams may not add a linked team, and may not remove a group-given
	// membership either: only teams without a link are theirs to set.
	if err := svc.SetUserTeams(ctx, user.ID, []int64{manual.ID}); err != nil {
		t.Fatalf("SetUserTeams: %v", err)
	}
	if !slices.Contains(memberEmails(t, q, linked.ID), "dev@example.com") {
		t.Error("SetUserTeams removed a group-given membership")
	}

	// Removing the link keeps the members; an admin removes them deliberately.
	if err := svc.UpdateTeam(ctx, linked.ID, access.TeamInput{Name: "Payments"}); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if !slices.Contains(memberEmails(t, q, linked.ID), "dev@example.com") {
		t.Error("unlinking removed the members")
	}
	team, err := q.GetTeam(context.Background(), linked.ID)
	if err != nil || team.IDPGroup != nil {
		t.Errorf("after unlinking: %+v, %v", team.IDPGroup, err)
	}
}

// A group name is an authorization key: it is stored exactly as given, so a
// name that merely looks like another after cleaning cannot inherit its team.
func TestGroupNamesAreNotRewritten(t *testing.T) {
	svc, _ := newService(t)
	ctx := asAdmin(context.Background())
	team, err := svc.CreateTeam(ctx, access.TeamInput{Name: "Payments", IDPGroup: "<b>payments</b>"})
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if team.IDPGroup == nil || *team.IDPGroup != "<b>payments</b>" {
		t.Errorf("group stored as %v, want the exact name", team.IDPGroup)
	}
}
