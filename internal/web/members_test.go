package web

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// The member editor can hold several lines; saving adds every chosen person,
// not only the first.
func TestTeamMemberEditorAddsEveryChosenPerson(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	for _, email := range []string{"one@example.com", "two@example.com"} {
		h.expect(h.get("/me", email), 200)
	}
	one, err := h.q.GetUserByEmail(context.Background(), "one@example.com")
	if err != nil {
		t.Fatal(err)
	}
	two, err := h.q.GetUserByEmail(context.Background(), "two@example.com")
	if err != nil {
		t.Fatal(err)
	}
	created := h.post("/admin/teams", admin, url.Values{"name": {"Pair"}})
	teamURL := strings.TrimSuffix(created.header.Get("HX-Redirect"), "?notice=created")
	if teamURL == "" {
		t.Fatalf("team not created: %d %s", created.status, created.body)
	}

	h.expect(h.post(teamURL+"/members", admin, url.Values{"user_id": {
		strconv.FormatInt(one.ID, 10), "", strconv.FormatInt(two.ID, 10),
	}}), 200)

	body := h.get(teamURL, admin).body
	for _, email := range []string{"one@example.com", "two@example.com"} {
		if !strings.Contains(body, email) {
			t.Errorf("team page does not list %s", email)
		}
	}
}
