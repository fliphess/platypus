package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"platypus/internal/access"
	"platypus/internal/authz"
	"platypus/internal/catalog"
	"platypus/internal/db"
	"platypus/internal/item"
	"platypus/internal/store"
)

// A secret scheduled for deletion is visible with its state, can be restored
// from its page, and is only readable again after that.
func TestDeletedSecretCanBeRestored(t *testing.T) {
	h := newHarness(t)
	secret := h.bootstrap()
	h.elevate(secret)
	h.addSecret("prod/payments/db", `{"password":"fake-password"}`)
	h.grant(editor, access.RuleInput{Kind: item.KindSecret, Pattern: "prod/*",
		Permissions: authz.Permissions{List: true, Edit: true, Reveal: true}})

	// The sync would store this: the secret is scheduled for deletion.
	deletedAt := time.Now()
	if err := h.catalog.PutSecret(context.Background(), store.Secret{
		Name: "prod/payments/db", CurrentVersionID: "v1", DeletedDate: &deletedAt,
	}, catalog.AccessOK, deletedAt); err != nil {
		t.Fatal(err)
	}
	h.secrets.MarkDeleted("prod/payments/db")

	list := h.get("/secrets", editor)
	if !strings.Contains(list.body, "deleted") {
		t.Errorf("the list should mark the deleted secret:\n%s", list.body)
	}

	detail := h.get(secretsURL(), editor)
	if !strings.Contains(detail.body, "Scheduled for deletion") || !strings.Contains(detail.body, "Restore this secret") {
		t.Errorf("the detail should offer to restore:\n%s", detail.body)
	}
	if h.post("/secrets/reveal", editor, url.Values{"name": {"prod/payments/db"}}).status == http.StatusOK {
		t.Error("a deleted secret must not be revealable")
	}

	h.expect(h.post("/secrets/undelete", editor, url.Values{"name": {"prod/payments/db"}}), http.StatusOK)
	after := h.get(secretsURL(), editor)
	if strings.Contains(after.body, "Scheduled for deletion") {
		t.Error("after restoring the banner must be gone")
	}
	if revealed := h.post("/secrets/reveal", editor, url.Values{"name": {"prod/payments/db"}}); revealed.status != http.StatusOK ||
		!strings.Contains(revealed.body, "fake-password") {
		t.Errorf("after restoring the value must be readable: %d", revealed.status)
	}

	events, err := h.q.ListAuditEvents(context.Background(), db.ListAuditEventsParams{MaxRows: 20})
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, event := range events {
		if event.Action == "item.undelete" {
			seen = true
		}
	}
	if !seen {
		t.Error("restoring a secret must be in the audit trail")
	}
}

func secretsURL() string { return "/secrets/item?name=prod/payments/db" }
