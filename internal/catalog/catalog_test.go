package catalog_test

import (
	"context"
	"testing"
	"time"

	"platypus/internal/catalog"
	"platypus/internal/database/dbtest"
	"platypus/internal/db"
	"platypus/internal/item"
	"platypus/internal/store"
)

// A sync that started before a change must not put the old state back when it
// finishes after it (Q03).
func TestOlderObservationsAreRejected(t *testing.T) {
	ctx := context.Background()
	cat := catalog.New(db.New(dbtest.New(t)))
	newer := time.Now().UTC().Truncate(time.Microsecond)
	older := newer.Add(-time.Hour)

	param := store.Parameter{Name: "/apps/gateway", Description: "new", Version: 2, LastModified: newer,
		Type: item.SSMTypeString, Tier: item.SSMTierStandard, DataType: "text"}
	if err := cat.PutParameter(ctx, param, catalog.AccessOK, time.Time{}); err != nil {
		t.Fatal(err)
	}
	stale := param
	stale.Description, stale.Version, stale.LastModified = "old", 1, older
	if err := cat.PutParameter(ctx, stale, catalog.AccessOK, time.Time{}); err != nil {
		t.Fatal(err)
	}
	entry, found, err := cat.Get(ctx, item.KindSSM, param.Name)
	if err != nil || !found {
		t.Fatalf("Get = %+v, %v, %v", entry, found, err)
	}
	if entry.Description != "new" || entry.SSMVersion != 2 {
		t.Errorf("the older observation overwrote the newer one: %+v", entry)
	}

	secret := store.Secret{Name: "prod/gateway", Description: "new", CurrentVersionID: "v2",
		LastChanged: newer, ARN: "arn:aws:secretsmanager:eu-west-1:1:secret:prod/gateway"}
	if err := cat.PutSecret(ctx, secret, catalog.AccessOK, time.Time{}); err != nil {
		t.Fatal(err)
	}
	staleSecret := secret
	staleSecret.Description, staleSecret.CurrentVersionID, staleSecret.LastChanged = "old", "v1", older
	if err := cat.PutSecret(ctx, staleSecret, catalog.AccessOK, time.Time{}); err != nil {
		t.Fatal(err)
	}
	entry, found, err = cat.Get(ctx, item.KindSecret, secret.Name)
	if err != nil || !found {
		t.Fatalf("Get = %+v, %v, %v", entry, found, err)
	}
	if entry.Description != "new" || entry.SecretVersionID != "v2" {
		t.Errorf("the older observation overwrote the newer one: %+v", entry)
	}
}
