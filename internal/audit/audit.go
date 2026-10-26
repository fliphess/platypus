// Package audit records who did what in platypus.
//
// Every event goes to two places: the audit_events table (shown to admins)
// and stdout as a JSON log line with log_type "audit" (for your log collector).
// Events never contain parameter or secret values.
package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"

	"platypus/internal/db"
)

// Outcome says how an action ended.
type Outcome string

const (
	Allowed Outcome = "allowed"
	Denied  Outcome = "denied"
	Error   Outcome = "error"
)

// Outcomes lists all outcomes, for filters.
var Outcomes = []Outcome{Allowed, Denied, Error}

// Event is one entry in the audit trail. Details holds extra context such as
// changed settings; it must never hold values.
type Event struct {
	Action  Action
	Outcome Outcome
	Kind    string
	Name    string
	Reason  string
	Details map[string]any
}

// Actor is who performed an action.
type Actor struct {
	UserID int64
	Email  string
}

// Request is where an action came from.
type Request struct {
	ClientIP  string
	UserAgent string
	RequestID string
}

// System actors for work that no user started.
var (
	ActorWorker = Actor{Email: "platypus-worker"}
	ActorCLI    = Actor{Email: "platypus-cli"}
)

type actorKey struct{}
type requestKey struct{}

// WithActor returns a context carrying the actor for later events.
func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

// WithRequest returns a context carrying request details for later events.
func WithRequest(ctx context.Context, request Request) context.Context {
	return context.WithValue(ctx, requestKey{}, request)
}

// ActorFrom returns the actor stored in ctx, if any.
func ActorFrom(ctx context.Context) Actor {
	actor, _ := ctx.Value(actorKey{}).(Actor)
	return actor
}

func requestFrom(ctx context.Context) Request {
	request, _ := ctx.Value(requestKey{}).(Request)
	return request
}

// Recorder writes audit events.
type Recorder struct {
	queries *db.Queries
	log     *zap.Logger
}

// NewRecorder returns a Recorder writing to the database behind queries.
func NewRecorder(queries *db.Queries, log *zap.Logger) *Recorder {
	return &Recorder{queries: queries, log: log}
}

// eventRow turns an event and the request context into the row to insert.
func (r *Recorder) eventRow(ctx context.Context, event Event) db.InsertAuditEventParams {
	actor := ActorFrom(ctx)
	request := requestFrom(ctx)

	details := event.Details
	if details == nil {
		details = map[string]any{}
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}

	var actorID *int64
	if actor.UserID != 0 {
		actorID = &actor.UserID
	}
	return db.InsertAuditEventParams{
		ActorID:      actorID,
		ActorEmail:   actor.Email,
		Action:       string(event.Action),
		Outcome:      string(event.Outcome),
		ResourceKind: event.Kind,
		ResourceName: event.Name,
		Reason:       event.Reason,
		ClientIP:     request.ClientIP,
		UserAgent:    request.UserAgent,
		RequestID:    request.RequestID,
		Details:      detailsJSON,
	}
}

// logEvent writes the JSON line for an event that was stored.
func (r *Recorder) logEvent(ctx context.Context, event Event) {
	actor := ActorFrom(ctx)
	request := requestFrom(ctx)
	details := event.Details
	if details == nil {
		details = map[string]any{}
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	r.log.Info("audit event",
		zap.String("log_type", "audit"),
		zap.String("action", string(event.Action)),
		zap.String("outcome", string(event.Outcome)),
		zap.Int64("actor_id", actor.UserID),
		zap.String("actor_email", actor.Email),
		zap.String("resource_kind", event.Kind),
		zap.String("resource_name", event.Name),
		zap.String("reason", event.Reason),
		zap.String("client_ip", request.ClientIP),
		zap.String("user_agent", request.UserAgent),
		zap.String("request_id", request.RequestID),
		zap.Any("details", json.RawMessage(detailsJSON)),
	)

}

// Record stores an event, taking actor and request details from ctx. When
// the database write fails the error is returned: callers about to show a
// value must not continue without an audit record.
func (r *Recorder) Record(ctx context.Context, event Event) error {
	if err := r.queries.InsertAuditEvent(ctx, r.eventRow(ctx, event)); err != nil {
		r.log.Error("could not store audit event", zap.String("action", string(event.Action)), zap.Error(err))
		return fmt.Errorf("store audit event: %w", err)
	}
	r.logEvent(ctx, event)
	return nil
}

// RecordTx stores an event in the same transaction as the change it
// describes. If the event can't be written the change rolls back: there is no
// state change without its audit record.
func (r *Recorder) RecordTx(ctx context.Context, q *db.Queries, event Event) error {
	if err := q.InsertAuditEvent(ctx, r.eventRow(ctx, event)); err != nil {
		r.log.Error("could not store audit event", zap.String("action", string(event.Action)), zap.Error(err))
		return fmt.Errorf("store audit event: %w", err)
	}
	r.logEvent(ctx, event)
	return nil
}

// RecordBestEffort records an event where a failed write must not stop the
// caller, such as a denial that is refused anyway. Failures are logged.
func (r *Recorder) RecordBestEffort(ctx context.Context, event Event) {
	_ = r.Record(ctx, event)
}
