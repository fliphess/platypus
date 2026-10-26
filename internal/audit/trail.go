package audit

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"platypus/internal/db"
)

// Filter selects audit events. Empty fields don't filter.
type Filter struct {
	Since      *time.Time
	Until      *time.Time
	ActorEmail string
	Action     string
	Outcome    string
	// Search matches any text shown for an event (actor, action, outcome,
	// resource, reason, details).
	Search string
}

// Trail reads and prunes the audit trail. Only admins get to use it.
type Trail struct {
	queries  *db.Queries
	recorder *Recorder
	now      func() time.Time
}

// NewTrail returns a Trail.
func NewTrail(queries *db.Queries, recorder *Recorder) *Trail {
	return &Trail{queries: queries, recorder: recorder, now: time.Now}
}

// List returns up to limit events matching f, newest first, older than
// beforeID (0 starts at the newest).
func (t *Trail) List(ctx context.Context, f Filter, beforeID int64, limit int32) ([]db.AuditEvent, error) {
	params := db.ListAuditEventsParams{
		Since:      f.Since,
		Until:      f.Until,
		ActorEmail: optional(strings.ToLower(f.ActorEmail)),
		Action:     optional(f.Action),
		Outcome:    optional(f.Outcome),
		MaxRows:    limit,
	}
	if f.Search != "" {
		params.Search = optional("%" + likeEscaper.Replace(strings.ToLower(f.Search)) + "%")
	}
	if beforeID > 0 {
		params.BeforeID = &beforeID
	}
	events, err := t.queries.ListAuditEvents(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	return events, nil
}

// pageParams are the filter fields the page query shares with List.
func pageParams(f Filter, limit int32, offset int32) db.ListAuditEventsPageParams {
	params := db.ListAuditEventsPageParams{
		MaxRows:   limit,
		RowOffset: offset,
	}
	params.Since = f.Since
	params.Until = f.Until
	params.ActorEmail = optional(strings.ToLower(f.ActorEmail))
	params.Action = optional(f.Action)
	params.Outcome = optional(f.Outcome)
	if f.Search != "" {
		params.Search = optional("%" + likeEscaper.Replace(strings.ToLower(f.Search)) + "%")
	}
	return params
}

func countParams(f Filter) db.CountAuditEventsParams {
	params := db.CountAuditEventsParams{}
	params.Since = f.Since
	params.Until = f.Until
	params.ActorEmail = optional(strings.ToLower(f.ActorEmail))
	params.Action = optional(f.Action)
	params.Outcome = optional(f.Outcome)
	if f.Search != "" {
		params.Search = optional("%" + likeEscaper.Replace(strings.ToLower(f.Search)) + "%")
	}
	return params
}

// Page returns one page of events and the total number matching f, so the
// trail can paginate instead of walking "older" links.
func (t *Trail) Page(ctx context.Context, f Filter, page int, limit int32) ([]db.AuditEvent, int64, error) {
	if page < 1 {
		page = 1
	}
	total, err := t.queries.CountAuditEvents(ctx, countParams(f))
	if err != nil {
		return nil, 0, fmt.Errorf("count audit events: %w", err)
	}
	offset := int64(page-1) * int64(limit)
	if offset > 1<<31-1 {
		offset = 1<<31 - 1
	}
	events, err := t.queries.ListAuditEventsPage(ctx, pageParams(f, limit, int32(offset)))
	if err != nil {
		return nil, 0, fmt.Errorf("list audit events: %w", err)
	}
	return events, total, nil
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// csvBatch is how many events are read per query while exporting.
const csvBatch = 1000

// WriteCSV writes every event matching f to w as CSV, newest first. The
// export itself is audited.
func (t *Trail) WriteCSV(ctx context.Context, w io.Writer, f Filter) error {
	if err := t.recorder.Record(ctx, Event{Action: ActionAuditExported, Outcome: Allowed,
		Details: map[string]any{"filter": f}}); err != nil {
		return err
	}

	out := csv.NewWriter(w)
	header := []string{"id", "occurred_at", "actor_email", "action", "outcome", "resource_kind",
		"resource_name", "reason", "client_ip", "user_agent", "request_id", "details"}
	if err := out.Write(header); err != nil {
		return err
	}

	var beforeID int64
	for {
		events, err := t.List(ctx, f, beforeID, csvBatch)
		if err != nil {
			return err
		}
		for _, e := range events {
			record := []string{
				strconv.FormatInt(e.ID, 10),
				e.OccurredAt.UTC().Format(time.RFC3339),
				e.ActorEmail, e.Action, e.Outcome, e.ResourceKind, e.ResourceName,
				e.Reason, e.ClientIP, e.UserAgent, e.RequestID, string(e.Details),
			}
			for i := range record {
				record[i] = csvSafe(record[i])
			}
			if err := out.Write(record); err != nil {
				return err
			}
			beforeID = e.ID
		}
		if len(events) < csvBatch {
			break
		}
	}
	out.Flush()
	return out.Error()
}

// csvSafe stops spreadsheet programs from running a cell as a formula
// ("CSV injection"): cells starting with a formula character get a quote.
func csvSafe(cell string) string {
	if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
		return "'" + cell
	}
	return cell
}

// pruneBatch is how many events one delete removes, keeping locks short.
const pruneBatch = 5000

// Prune deletes events older than retentionDays and records the attempt
// before anything is deleted, then its outcome. The attempt record means a
// crash or a failure midway can never leave deleted history without a trace;
// a retention of 0 deletes everything older than now (useful in CI).
func (t *Trail) Prune(ctx context.Context, retentionDays int) (int64, error) {
	before := t.now().AddDate(0, 0, -retentionDays)
	if err := t.recorder.Record(ctx, Event{Action: ActionAuditPruned, Outcome: Allowed,
		Details: map[string]any{"phase": "started", "before": before, "retention_days": retentionDays}}); err != nil {
		// Without the attempt record, deleting would be unaccountable.
		return 0, fmt.Errorf("record prune attempt: %w", err)
	}
	var total int64
	for {
		deleted, err := t.queries.PruneAuditEvents(ctx, db.PruneAuditEventsParams{Before: before, BatchSize: pruneBatch})
		if err != nil {
			t.recorder.RecordBestEffort(ctx, Event{Action: ActionAuditPruned, Outcome: Error,
				Reason:  "pruning failed",
				Details: map[string]any{"phase": "failed", "deleted": total, "before": before}})
			return total, fmt.Errorf("prune audit events: %w", err)
		}
		total += deleted
		if deleted < pruneBatch {
			break
		}
	}
	err := t.recorder.Record(ctx, Event{Action: ActionAuditPruned, Outcome: Allowed,
		Details: map[string]any{"phase": "completed", "deleted": total, "before": before, "retention_days": retentionDays}})
	return total, err
}
