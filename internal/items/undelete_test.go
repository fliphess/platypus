package items_test

import (
	"context"
	"testing"
	"time"

	"platypus/internal/authz"
	"platypus/internal/catalog"
	"platypus/internal/item"
	"platypus/internal/store"
)

// A secret scheduled for deletion stays visible with its deletion date, can't
// be read until it is restored, and restoring needs edit permission.
func TestUndeleteSecret(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	dev := subject(rule(item.KindSecret, "prod/*", authz.Permissions{
		List: true, Edit: true, Reveal: true,
	}))
	deletable := time.Now()

	f.secrets.MarkDeleted("prod/payments/db")
	if err := f.catalog.PutSecret(ctx, store.Secret{
		Name: "prod/payments/db", CurrentVersionID: "v1", DeletedDate: &deletable,
	}, catalog.AccessOK, time.Now()); err != nil {
		t.Fatal(err)
	}

	detail, err := f.svc.Get(ctx, dev, item.KindSecret, "prod/payments/db")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if detail.DeletedAt == nil {
		t.Fatal("the detail doesn't show that the secret is scheduled for deletion")
	}
	if _, err := f.svc.Reveal(ctx, dev, item.KindSecret, "prod/payments/db", ""); err == nil {
		t.Error("a deleted secret must not be readable")
	}

	if err := f.svc.Undelete(ctx, dev, "prod/payments/db"); err != nil {
		t.Fatalf("Undelete: %v", err)
	}
	detail, err = f.svc.Get(ctx, dev, item.KindSecret, "prod/payments/db")
	if err != nil || detail.DeletedAt != nil {
		t.Errorf("after restoring: deleted = %v, err = %v", detail.DeletedAt, err)
	}
	if _, err := f.svc.Reveal(ctx, dev, item.KindSecret, "prod/payments/db", ""); err != nil {
		t.Errorf("after restoring the value must be readable: %v", err)
	}

	if err := f.svc.Undelete(ctx, dev, "prod/payments/db"); err == nil {
		t.Error("restoring a live secret must be refused")
	}

	// Without edit permission there is nothing to restore.
	viewer := subject(rule(item.KindSecret, "prod/*", authz.Permissions{List: true}))
	if err := f.svc.Undelete(ctx, viewer, "prod/payments/db"); err == nil {
		t.Error("restoring without edit permission must be refused")
	}
}
