package worker

import (
	"context"
	"net/url"
	"testing"
	"time"

	"platypus/internal/seal"

	"go.uber.org/zap"

	"platypus/internal/audit"
	"platypus/internal/bootstrap"
	"platypus/internal/catalog"
	"platypus/internal/config"
	"platypus/internal/database/dbtest"
	"platypus/internal/db"
	"platypus/internal/item"
	"platypus/internal/itemsync"
	"platypus/internal/lockout"
	"platypus/internal/mfa"
	"platypus/internal/ratelimit"
	"platypus/internal/sensitive"
	"platypus/internal/session"
	"platypus/internal/store"
	"platypus/internal/store/memstore"
)

type fixture struct {
	worker  *Worker
	q       *db.Queries
	catalog *catalog.Catalog
	params  *memstore.Parameters
	clock   *time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pool := dbtest.New(t)
	q := db.New(pool)
	recorder := audit.NewRecorder(q, zap.NewNop())
	guard := lockout.NewGuard(q, recorder)
	sealer, _ := seal.New(sensitive.New(config.TestEncryptionKey))
	publicURL, _ := url.Parse("https://platypus.example.com")
	mfaService, err := mfa.NewService(pool, sealer, publicURL, guard, recorder)
	if err != nil {
		t.Fatal(err)
	}
	params := memstore.NewParameters()
	secrets := memstore.NewSecrets()
	cat := catalog.New(q)

	w := New(pool,
		itemsync.NewJob(cat, q, params, secrets, zap.NewNop()),
		bootstrap.NewService(pool, params, mfaService, guard, recorder, bootstrap.Config{TokenParam: "/platypus/token", TokenTTL: time.Hour}),
		session.NewManager(q, time.Hour, time.Hour, true),
		ratelimit.New(q),
		Config{SyncInterval: time.Minute, SyncTimeout: time.Hour, AccessRecheckInterval: 24 * time.Hour},
		zap.NewNop())
	clock := time.Now()
	w.now = func() time.Time { return clock }
	return fixture{worker: w, q: q, catalog: cat, params: params, clock: &clock}
}

func (f fixture) syncRuns(t *testing.T) int {
	t.Helper()
	var count int
	latest, err := f.q.GetLatestSyncRun(context.Background())
	if err == nil {
		count = int(latest.ID)
	}
	return count
}

func TestRunOnceIssuesTokenAndSyncs(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.params.Create(ctx, store.NewParameter{Name: "/a/b", Value: sensitive.New("v"), Type: "String", Tier: "Standard"}); err != nil {
		t.Fatal(err)
	}

	f.worker.runOnce(ctx)

	if _, err := f.params.Value(ctx, "/platypus/token", 0); err != nil {
		t.Errorf("no bootstrap token in SSM: %v", err)
	}
	if _, found, _ := f.catalog.Get(ctx, item.KindSSM, "/a/b"); !found {
		t.Error("the first run should sync the catalog")
	}
	latest, err := f.q.GetLatestSyncRun(ctx)
	if err != nil || !latest.RecheckAccess || latest.Trigger != "schedule" {
		t.Errorf("first sync = %+v, %v (want a scheduled run with a full access check)", latest, err)
	}
}

func TestSyncSchedule(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	f.worker.runOnce(ctx)
	runs := f.syncRuns(t)

	// Within the interval nothing happens.
	*f.clock = f.clock.Add(30 * time.Second)
	f.worker.runOnce(ctx)
	if f.syncRuns(t) != runs {
		t.Error("a sync ran before the interval passed")
	}

	// An admin's request runs at once, and is used up.
	if err := f.q.RequestSync(ctx, db.RequestSyncParams{RequestedBy: new("admin@example.com"), RecheckAccess: true}); err != nil {
		t.Fatal(err)
	}
	f.worker.runOnce(ctx)
	latest, _ := f.q.GetLatestSyncRun(ctx)
	if f.syncRuns(t) != runs+1 || latest.Trigger != "manual" || !latest.RecheckAccess {
		t.Errorf("manual sync = %+v", latest)
	}
	f.worker.runOnce(ctx)
	if f.syncRuns(t) != runs+1 {
		t.Error("a sync request ran twice")
	}

	// After the interval the schedule runs again, without a full access check
	// (the last one is recent).
	*f.clock = time.Now().Add(2 * time.Minute)
	f.worker.runOnce(ctx)
	latest, _ = f.q.GetLatestSyncRun(ctx)
	if f.syncRuns(t) != runs+2 || latest.Trigger != "schedule" || latest.RecheckAccess {
		t.Errorf("scheduled sync = %+v", latest)
	}
}

func TestNoTokenAfterBootstrap(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.q.SetBootstrapped(ctx, true); err != nil {
		t.Fatal(err)
	}
	f.worker.runOnce(ctx)
	if _, err := f.params.Value(ctx, "/platypus/token", 0); err == nil {
		t.Error("a bootstrapped platypus must not issue tokens")
	}
}

func TestAliveFailsWhenRoundsStop(t *testing.T) {
	f := newFixture(t)
	if err := f.worker.Alive(); err != nil {
		t.Errorf("a starting worker is alive: %v", err)
	}
	f.worker.runOnce(context.Background())
	if err := f.worker.Alive(); err != nil {
		t.Errorf("right after a round: %v", err)
	}
	*f.clock = f.clock.Add(2 * time.Hour)
	if err := f.worker.Alive(); err == nil {
		t.Error("a worker without a finished round for two hours should not be alive")
	}
}

// A job whose lock another session holds doesn't run.
func TestJobSkippedWhileLockHeld(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	conn, err := f.worker.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(lockSync)); err != nil {
		t.Fatal(err)
	}

	f.worker.runOnce(ctx)
	if f.syncRuns(t) != 0 {
		t.Error("the sync ran while another session held its lock")
	}
	if f.worker.skipped["sync"] != 1 {
		t.Errorf("skipped = %v, want the sync counted once", f.worker.skipped)
	}
}
