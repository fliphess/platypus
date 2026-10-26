package web

import (
	"context"
	"strings"
	"testing"

	"platypus/internal/db"
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
