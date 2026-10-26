// Package worker runs the background jobs: the catalog sync, issuing the
// bootstrap token and housekeeping. It runs in its own Deployment, never in
// the web pods. Every job takes a Postgres advisory lock, so a second worker
// (for example during a rollout) never runs a job at the same time.
package worker

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"platypus/internal/audit"
	"platypus/internal/bootstrap"
	"platypus/internal/database"
	"platypus/internal/db"
	"platypus/internal/itemsync"
	"platypus/internal/ratelimit"
	"platypus/internal/session"
)

// Advisory lock keys, one per job.
const (
	lockSync         = 7461101
	lockBootstrap    = 7461102
	lockHousekeeping = 7461103
)

const (
	// tick is how often the worker looks for work, such as a "Sync now" request.
	tick = 10 * time.Second
	// housekeepingInterval is how often expired sessions and counters are removed.
	housekeepingInterval = 10 * time.Minute
	// syncRunRetention is how long sync history is kept.
	syncRunRetention = 30 * 24 * time.Hour
	// shortJobTimeout bounds the jobs other than the sync.
	shortJobTimeout = 5 * time.Minute
	// skipsBeforeWarning is how many ticks in a row a job may find its lock
	// held by another worker before that is logged.
	skipsBeforeWarning = 30
)

// Config holds the worker settings.
type Config struct {
	SyncInterval          time.Duration
	SyncTimeout           time.Duration
	AccessRecheckInterval time.Duration
}

// Worker runs the jobs.
type Worker struct {
	pool      *pgxpool.Pool
	queries   *db.Queries
	sync      *itemsync.Job
	bootstrap *bootstrap.Service
	sessions  *session.Manager
	limiter   *ratelimit.Limiter
	cfg       Config
	log       *zap.Logger
	now       func() time.Time

	lastHousekeeping time.Time
	// skipped counts, per job, the ticks in a row another worker held its lock.
	skipped map[string]int
	// lastRound is when the worker last finished a round of jobs, in Unix
	// nanoseconds. The liveness check reads it from another goroutine.
	lastRound atomic.Int64
}

// New returns a Worker.
func New(pool *pgxpool.Pool, sync *itemsync.Job, bootstrapService *bootstrap.Service,
	sessions *session.Manager, limiter *ratelimit.Limiter, cfg Config, log *zap.Logger) *Worker {
	return &Worker{
		pool:      pool,
		queries:   db.New(pool),
		sync:      sync,
		bootstrap: bootstrapService,
		sessions:  sessions,
		limiter:   limiter,
		cfg:       cfg,
		log:       log,
		now:       time.Now,
		skipped:   map[string]int{},
	}
}

// Alive reports an error when the worker hasn't finished a round of jobs for
// longer than a round can take: something is stuck despite the time limits,
// and a restart is the way out. It is the worker's liveness check.
func (w *Worker) Alive() error {
	last := w.lastRound.Load()
	if last == 0 {
		return nil // still starting
	}
	limit := w.cfg.SyncTimeout + 2*shortJobTimeout + 2*tick
	if since := w.now().Sub(time.Unix(0, last)); since > limit {
		return fmt.Errorf("no round of jobs finished in %s", since.Round(time.Second))
	}
	return nil
}

// Run works until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	ctx = audit.WithActor(ctx, audit.ActorWorker)
	w.lastRound.Store(w.now().UnixNano())
	w.runJob(ctx, "close unfinished sync runs", lockSync, shortJobTimeout, w.queries.FailUnfinishedSyncRuns)

	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		w.runOnce(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// runOnce gives every job a chance to run. A failing job is logged and
// retried on a later tick; it doesn't stop the others.
func (w *Worker) runOnce(ctx context.Context) {
	w.runJob(ctx, "bootstrap token", lockBootstrap, shortJobTimeout, w.ensureBootstrapToken)
	w.runJob(ctx, "sync", lockSync, w.cfg.SyncTimeout, w.syncIfDue)
	if w.now().Sub(w.lastHousekeeping) >= housekeepingInterval {
		w.runJob(ctx, "housekeeping", lockHousekeeping, shortJobTimeout, w.housekeeping)
	}
	w.lastRound.Store(w.now().UnixNano())
}

// runJob runs a job under its lock and time limit. A job whose lock another
// worker holds is skipped; when that goes on for long, it is logged, because
// a lock held by a stuck session would otherwise stop the job silently.
func (w *Worker) runJob(ctx context.Context, name string, lock int64, timeout time.Duration, job func(context.Context) error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ran, err := w.runSafely(ctx, name, lock, job)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		w.log.Error("job took too long and was stopped", zap.String("job", name), zap.Duration("timeout", timeout), zap.Error(err))
	case err != nil && !errors.Is(err, context.Canceled):
		w.log.Error("job failed", zap.String("job", name), zap.Error(err))
	}

	if ran || err != nil {
		w.skipped[name] = 0
		return
	}
	w.skipped[name]++
	if w.skipped[name]%skipsBeforeWarning == 0 {
		w.log.Warn("job skipped: another worker holds its lock", zap.String("job", name), zap.Int("ticks_in_a_row", w.skipped[name]))
	}
}

// runSafely runs one job and turns a panic into a failed round. Without
// this, one bad item would take the worker down and nothing would sync again
// until Kubernetes restarted it.
func (w *Worker) runSafely(ctx context.Context, name string, lock int64, job func(context.Context) error) (ran bool, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			w.log.Error("job panicked", zap.String("job", name), zap.Any("panic", recovered), zap.Stack("stack"))
			err = fmt.Errorf("job panicked: %v", recovered)
		}
	}()
	return database.WithTryLock(ctx, w.pool, lock, job)
}

func (w *Worker) ensureBootstrapToken(ctx context.Context) error {
	issued, err := w.bootstrap.EnsureToken(ctx)
	if issued {
		w.log.Info("issued a bootstrap token; read it from SSM to set up platypus")
	}
	return err
}

// syncIfDue runs a sync when an admin asked for one or the interval passed.
// It re-checks access to every item when the last full check is too old.
func (w *Worker) syncIfDue(ctx context.Context) error {
	trigger := itemsync.TriggerSchedule
	recheck := false

	request, err := w.queries.TakeSyncRequest(ctx)
	switch {
	case err == nil:
		trigger, recheck = itemsync.TriggerManual, request.SyncRecheckAccess
	case !database.IsNoRows(err):
		return err
	default:
		due, err := w.scheduledSyncDue(ctx)
		if err != nil || !due {
			return err
		}
	}

	if !recheck {
		last, err := w.queries.GetLatestSuccessfulRecheck(ctx)
		if err != nil && !database.IsNoRows(err) {
			return err
		}
		recheck = database.IsNoRows(err) || w.now().Sub(last) >= w.cfg.AccessRecheckInterval
	}

	result, err := w.sync.Run(ctx, trigger, recheck)
	if err != nil {
		return err
	}
	w.log.Info("sync finished", zap.String("trigger", string(trigger)), zap.Bool("recheck_access", recheck),
		zap.Int32("parameters", result.Parameters), zap.Int32("secrets", result.Secrets),
		zap.Int32("access_checked", result.AccessChecked))
	return nil
}

// scheduledSyncDue reports whether the last sync started at least one sync
// interval ago. The database knows, so restarts and extra workers don't
// change the rhythm.
func (w *Worker) scheduledSyncDue(ctx context.Context) (bool, error) {
	latest, err := w.queries.GetLatestSyncRun(ctx)
	if database.IsNoRows(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return w.now().Sub(latest.StartedAt) >= w.cfg.SyncInterval, nil
}

func (w *Worker) housekeeping(ctx context.Context) error {
	w.lastHousekeeping = w.now()
	return errors.Join(
		w.sessions.Cleanup(ctx),
		w.limiter.Cleanup(ctx),
		w.queries.DeleteSyncRunsBefore(ctx, w.now().Add(-syncRunRetention)),
	)
}
