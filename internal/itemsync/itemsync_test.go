package itemsync

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"platypus/internal/catalog"
	"platypus/internal/database/dbtest"
	"platypus/internal/db"
	"platypus/internal/item"
	"platypus/internal/sensitive"
	"platypus/internal/store"
	"platypus/internal/store/memstore"
)

func TestSync(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t)
	q := db.New(pool)
	cat := catalog.New(q)
	params := memstore.NewParameters()
	secrets := memstore.NewSecrets()
	job := NewJob(cat, q, params, secrets, zap.NewNop())
	job.pace = time.Millisecond

	for _, name := range []string{"/a/one", "/a/two", "/a/denied"} {
		if _, err := params.Create(ctx, store.NewParameter{Name: name, Value: sensitive.New("v"), Type: "String", Tier: "Standard"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := secrets.Create(ctx, store.NewSecret{Name: "prod/db", Value: sensitive.New("v")}); err != nil {
		t.Fatal(err)
	}
	params.Deny("/a/denied")

	result, err := job.Run(ctx, TriggerManual, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Parameters != 3 || result.Secrets != 1 || result.AccessChecked != 4 {
		t.Errorf("result = %+v", result)
	}

	visible := func(kind item.Kind, name string) bool {
		_, found, err := cat.Get(ctx, kind, name)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	if !visible(item.KindSSM, "/a/one") || !visible(item.KindSecret, "prod/db") {
		t.Error("accessible items are not visible")
	}
	if visible(item.KindSSM, "/a/denied") {
		t.Error("an item platypus can't access is visible")
	}

	// A second sync removes what AWS no longer has and rechecks changed items.
	fresh := memstore.NewParameters()
	if _, err := fresh.Create(ctx, store.NewParameter{Name: "/a/one", Value: sensitive.New("v"), Type: "String", Tier: "Standard"}); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Write(ctx, "/a/one", sensitive.New("v2"), ""); err != nil { // now at version 2
		t.Fatal(err)
	}
	job.parameters = fresh
	result, err = job.Run(ctx, TriggerSchedule, false)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if visible(item.KindSSM, "/a/two") {
		t.Error("a parameter deleted in AWS is still in the catalog")
	}
	// /a/one changed (version 2), so its access is checked again.
	if result.AccessChecked != 1 || !visible(item.KindSSM, "/a/one") {
		t.Errorf("second run = %+v", result)
	}

	// A recheck checks every item again.
	result, err = job.Run(ctx, TriggerManual, true)
	if err != nil || result.AccessChecked != 2 {
		t.Errorf("recheck = %+v, %v", result, err)
	}

	latest, err := q.GetLatestSyncRun(ctx)
	if err != nil || latest.Status != "succeeded" || !latest.RecheckAccess {
		t.Errorf("latest run = %+v, %v", latest, err)
	}
}
