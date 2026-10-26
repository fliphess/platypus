// Package appstate holds the application-wide switches: whether platypus is
// bootstrapped, whether access is blocked, and requests for a sync.
package appstate

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"platypus/internal/audit"
	"platypus/internal/database"
	"platypus/internal/db"
)

// State is a snapshot of the switches.
type State struct {
	Bootstrapped bool
	Blocked      bool
	BlockedBy    string
	BlockedAt    time.Time
}

// Service reads and changes the state.
type Service struct {
	pool    *pgxpool.Pool
	queries *db.Queries
	audit   *audit.Recorder
}

// NewService returns a Service.
func NewService(pool *pgxpool.Pool, recorder *audit.Recorder) *Service {
	return &Service{pool: pool, queries: db.New(pool), audit: recorder}
}

// Get returns the current state.
func (s *Service) Get(ctx context.Context) (State, error) {
	row, err := s.queries.GetAppState(ctx)
	if err != nil {
		return State{}, fmt.Errorf("load app state: %w", err)
	}
	state := State{Bootstrapped: row.Bootstrapped, Blocked: row.BlockedAt != nil}
	if row.BlockedAt != nil {
		state.BlockedAt = *row.BlockedAt
	}
	if row.BlockedBy != nil {
		state.BlockedBy = *row.BlockedBy
	}
	return state, nil
}

// SetBlocked turns the block switch on or off. While on, only admins can use
// platypus, and nobody can reveal or change values.
func (s *Service) SetBlocked(ctx context.Context, blocked bool) error {
	action := audit.ActionBlockOff
	if blocked {
		action = audit.ActionBlockOn
	}
	err := database.InTx(ctx, s.pool, func(q *db.Queries) error {
		if blocked {
			blockedBy := audit.ActorFrom(ctx).Email
			if err := q.SetBlocked(ctx, &blockedBy); err != nil {
				return err
			}
		} else if err := q.ClearBlocked(ctx); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, q, audit.Event{Action: action, Outcome: audit.Allowed})
	})
	if err != nil {
		return fmt.Errorf("set block switch: %w", err)
	}
	return nil
}

// RequestSync asks the worker to sync now. With recheckAccess it also
// re-checks platypus's own access to every item.
func (s *Service) RequestSync(ctx context.Context, recheckAccess bool) error {
	requestedBy := audit.ActorFrom(ctx).Email
	err := database.InTx(ctx, s.pool, func(q *db.Queries) error {
		if err := q.RequestSync(ctx, db.RequestSyncParams{
			RequestedBy:   &requestedBy,
			RecheckAccess: recheckAccess,
		}); err != nil {
			return err
		}
		return s.audit.RecordTx(ctx, q, audit.Event{Action: audit.ActionSyncRequested, Outcome: audit.Allowed,
			Details: map[string]any{"recheck_access": recheckAccess}})
	})
	if err != nil {
		return fmt.Errorf("request sync: %w", err)
	}
	return nil
}

// LatestSync returns the most recent sync run, if there was one.
func (s *Service) LatestSync(ctx context.Context) (*db.SyncRun, error) {
	run, err := s.queries.GetLatestSyncRun(ctx)
	if database.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load latest sync: %w", err)
	}
	return &run, nil
}
