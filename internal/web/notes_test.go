package web

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"platypus/internal/access"
	"platypus/internal/authz"
	"platypus/internal/db"
	"platypus/internal/item"
)

// The orphaned notes page is a list like any other: a table with a header and
// the same pager, not a run of bare rows.
func TestOrphanedNotesPageUsesTheListLayout(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)

	if err := h.q.SaveNote(context.Background(), db.SaveNoteParams{
		Kind: "ssm", Name: "/gone/item", Body: "the item is gone", UpdatedBy: admin,
	}); err != nil {
		t.Fatal(err)
	}

	body := h.get("/admin/notes", admin).body
	for _, want := range []string{`<th>Kind</th>`, `<th>Item</th>`, `<th>Updated</th>`, `<th>Note</th>`, `class="pager"`, `the item is gone`} {
		if !strings.Contains(body, want) {
			t.Errorf("the orphaned notes page is missing %q", want)
		}
	}
}

// The list's expanded row shows the note text and links to the item's page:
// a note that says "do not edit" must be readable without opening the editor.
func TestListShowsNoteAndItemLink(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	h.grant(admin, access.RuleInput{Kind: item.KindSSM, Pattern: "/*",
		Permissions: authz.Permissions{List: true}})
	h.addParameter("/apps/noted", "a value")

	if err := h.q.SaveNote(context.Background(), db.SaveNoteParams{
		Kind: "ssm", Name: "/apps/noted", Body: "DO NOT EDIT", UpdatedBy: admin,
	}); err != nil {
		t.Fatal(err)
	}

	body := h.get("/ssm", admin).body
	if !strings.Contains(body, "DO NOT EDIT") {
		t.Error("the list does not show the note text")
	}
	// html/template percent-encodes the slashes in the query value.
	if !strings.Contains(body, "/ssm/item?name=%2fapps%2fnoted") {
		t.Error("the list has no link to the item's page")
	}
}

// A group-linked team is a fixed line on the user's Teams card: it shows the
// team and its group, and offers no remove button (members come from the IdP).
func TestUserTeamsCardShowsLinkedTeamAsFixed(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	h.get("/me", editor)
	user, err := h.q.GetUserByEmail(context.Background(), editor)
	if err != nil {
		t.Fatal(err)
	}
	group := "payments"
	team, err := h.q.CreateTeam(context.Background(), db.CreateTeamParams{Name: "Payments", IDPGroup: &group})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.q.AddTeamMember(context.Background(), db.AddTeamMemberParams{TeamID: team.ID, UserID: user.ID}); err != nil {
		t.Fatal(err)
	}

	body := h.get("/admin/users/"+strconv.FormatInt(user.ID, 10), admin).body
	row := regexp.MustCompile(`(?s)<div class="choice-row" data-choice-row>.*?Payments.*?</div>`).FindString(body)
	if row == "" {
		t.Fatalf("the linked team has no line in the team editor")
	}
	if !strings.Contains(row, "choice-label") || !strings.Contains(row, `>payments<`) {
		t.Errorf("the linked team line does not show its group: %s", row)
	}
	if strings.Contains(row, "data-remove-choice") {
		t.Errorf("a linked team offers a remove button: %s", row)
	}
}
