// Package itemsync refreshes the catalog from AWS: it lists every parameter
// and secret, removes what disappeared, and checks which items platypus
// itself can access. Items platypus can't access stay hidden.
package itemsync

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"platypus/internal/catalog"
	"platypus/internal/db"
	"platypus/internal/item"
	"platypus/internal/store"
)

// Trigger says why a sync runs.
type Trigger string

const (
	TriggerSchedule Trigger = "schedule"
	TriggerManual   Trigger = "manual"
)

// accessChecksPerSecond paces access checks, leaving AWS API capacity for the
// applications that read their configuration from SSM.
const accessChecksPerSecond = 10

// Job runs syncs.
type Job struct {
	catalog    *catalog.Catalog
	queries    *db.Queries
	parameters store.Parameters
	secrets    store.Secrets
	log        *zap.Logger
	pace       time.Duration
}

// NewJob returns a Job.
func NewJob(cat *catalog.Catalog, queries *db.Queries, parameters store.Parameters, secrets store.Secrets, log *zap.Logger) *Job {
	return &Job{
		catalog:    cat,
		queries:    queries,
		parameters: parameters,
		secrets:    secrets,
		log:        log,
		pace:       time.Second / accessChecksPerSecond,
	}
}

// Result counts what a sync did.
type Result struct {
	Parameters    int32
	Secrets       int32
	AccessChecked int32
}

// Run performs one sync and records it in sync_runs. With recheckAccess the
// access of every item is checked again, not only of new and changed ones.
func (j *Job) Run(ctx context.Context, trigger Trigger, recheckAccess bool) (Result, error) {
	run, err := j.queries.StartSyncRun(ctx, db.StartSyncRunParams{Trigger: string(trigger), RecheckAccess: recheckAccess})
	if err != nil {
		return Result{}, fmt.Errorf("start sync run: %w", err)
	}
	// The database clock marks this run, so comparisons with synced_at are
	// exact (Postgres keeps microseconds, Go nanoseconds).
	startedAt := run.StartedAt

	result, err := j.sync(ctx, startedAt, recheckAccess)

	status, message := "succeeded", ""
	if err != nil {
		status, message = "failed", err.Error()
	}
	finishErr := j.queries.FinishSyncRun(context.WithoutCancel(ctx), db.FinishSyncRunParams{
		ID:             run.ID,
		Status:         status,
		ParametersSeen: result.Parameters,
		SecretsSeen:    result.Secrets,
		AccessChecked:  result.AccessChecked,
		Message:        message,
	})
	return result, errors.Join(err, finishErr)
}

func (j *Job) sync(ctx context.Context, startedAt time.Time, recheckAccess bool) (Result, error) {
	var result Result

	err := j.parameters.List(ctx, func(p store.Parameter) error {
		result.Parameters++
		return j.catalog.PutParameter(ctx, p, catalog.AccessUnknown, startedAt)
	})
	if err != nil {
		return result, fmt.Errorf("list parameters: %w", err)
	}
	err = j.secrets.List(ctx, func(s store.Secret) error {
		result.Secrets++
		return j.catalog.PutSecret(ctx, s, catalog.AccessUnknown, startedAt)
	})
	if err != nil {
		return result, fmt.Errorf("list secrets: %w", err)
	}

	// Only after both complete listings: remove what AWS no longer has.
	for _, kind := range item.Kinds {
		removed, err := j.catalog.RemoveNotSyncedSince(ctx, kind, startedAt)
		if err != nil {
			return result, fmt.Errorf("remove deleted %s: %w", kind.PluralNoun(), err)
		}
		if removed > 0 {
			j.log.Info("removed items no longer in AWS", zap.String("kind", string(kind)), zap.Int64("count", removed))
		}
	}

	checkedBefore := time.Time{}
	if recheckAccess {
		checkedBefore = startedAt
	}
	for _, kind := range item.Kinds {
		checked, err := j.checkAccess(ctx, kind, checkedBefore)
		result.AccessChecked += checked
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

// checkAccess checks every item of kind whose access is unknown or was
// checked before checkedBefore.
func (j *Job) checkAccess(ctx context.Context, kind item.Kind, checkedBefore time.Time) (int32, error) {
	names, err := j.catalog.NamesToCheck(ctx, kind, checkedBefore)
	if err != nil {
		return 0, fmt.Errorf("list %s to check: %w", kind.PluralNoun(), err)
	}

	ticker := time.NewTicker(j.pace)
	defer ticker.Stop()

	var checked int32
	for _, name := range names {
		select {
		case <-ctx.Done():
			return checked, ctx.Err()
		case <-ticker.C:
		}

		var err error
		if kind == item.KindSSM {
			err = j.parameters.CheckAccess(ctx, name)
		} else {
			err = j.secrets.CheckAccess(ctx, name)
		}

		access := catalog.AccessOK
		switch {
		case err == nil:
		case errors.Is(err, store.ErrAccessDenied):
			access = catalog.AccessDenied
			j.log.Info("platypus has no access to an item; hiding it", zap.String("kind", string(kind)), zap.String("name", name))
		case errors.Is(err, store.ErrNotFound):
			continue // deleted since the listing; the next sync removes it
		default:
			return checked, fmt.Errorf("check access to %s: %w", name, err)
		}
		if err := j.catalog.SetAccess(ctx, kind, name, access); err != nil {
			return checked, err
		}
		checked++
	}
	return checked, nil
}
