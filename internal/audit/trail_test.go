package audit_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"testing"

	"go.uber.org/zap"

	"platypus/internal/audit"
	"platypus/internal/database/dbtest"
	"platypus/internal/db"
)

func TestTrail(t *testing.T) {
	ctx := audit.WithActor(context.Background(), audit.Actor{UserID: 1, Email: "admin@example.com"})
	ctx = audit.WithRequest(ctx, audit.Request{ClientIP: "10.0.0.1", UserAgent: "test", RequestID: "req-1"})
	pool := dbtest.New(t)
	q := db.New(pool)
	recorder := audit.NewRecorder(q, zap.NewNop())
	trail := audit.NewTrail(q, recorder)

	for _, e := range []audit.Event{
		{Action: audit.ActionItemView, Outcome: audit.Allowed, Kind: "ssm", Name: "/apps/a"},
		{Action: audit.ActionItemReveal, Outcome: audit.Denied, Kind: "ssm", Name: "/apps/b", Reason: "no permission"},
		{Action: audit.ActionItemNote, Outcome: audit.Allowed, Kind: "ssm", Name: "/other/c",
			Details: map[string]any{"note": "=HYPERLINK(\"http://evil\")"}},
	} {
		if err := recorder.Record(ctx, e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	all, err := trail.List(ctx, audit.Filter{}, 0, 10)
	if err != nil || len(all) != 3 || all[0].Action != string(audit.ActionItemNote) {
		t.Fatalf("List = %d events, %v (want 3, newest first)", len(all), err)
	}
	if all[0].ClientIP != "10.0.0.1" || all[0].ActorEmail != "admin@example.com" || all[0].RequestID != "req-1" {
		t.Errorf("request details not stored: %+v", all[0])
	}

	denied, _ := trail.List(ctx, audit.Filter{Outcome: "denied"}, 0, 10)
	apps, _ := trail.List(ctx, audit.Filter{Search: "/apps/"}, 0, 10)
	older, _ := trail.List(ctx, audit.Filter{}, all[0].ID, 10)
	if len(denied) != 1 || len(apps) != 2 || len(older) != 2 {
		t.Errorf("filters: denied=%d apps=%d older=%d", len(denied), len(apps), len(older))
	}

	var buf bytes.Buffer
	if err := trail.WriteCSV(ctx, &buf, audit.Filter{Action: string(audit.ActionItemNote)}); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(records) != 2 {
		t.Fatalf("CSV = %v, %v", records, err)
	}

	pruned, err := trail.Prune(ctx, 0)
	if err != nil || pruned < 4 { // 3 events plus the export event
		t.Fatalf("Prune = %d, %v", pruned, err)
	}
	remaining, _ := trail.List(ctx, audit.Filter{}, 0, 10)
	// The attempt and the outcome both survive: pruning is never unaccountable.
	if len(remaining) != 2 {
		t.Fatalf("after prune: %+v (want the started and completed records)", remaining)
	}
	for _, event := range remaining {
		if event.Action != string(audit.ActionAuditPruned) {
			t.Errorf("after prune: %+v", remaining)
		}
	}
}

func TestCSVCellsCantBeFormulas(t *testing.T) {
	ctx := audit.WithActor(context.Background(), audit.Actor{Email: "=cmd|' /C calc'!A0"})
	pool := dbtest.New(t)
	q := db.New(pool)
	recorder := audit.NewRecorder(q, zap.NewNop())
	recorder.RecordBestEffort(ctx, audit.Event{Action: audit.ActionItemView, Outcome: audit.Allowed, Name: "+1+1"})

	var buf bytes.Buffer
	if err := audit.NewTrail(q, recorder).WriteCSV(ctx, &buf, audit.Filter{Action: string(audit.ActionItemView)}); err != nil {
		t.Fatal(err)
	}
	records, _ := csv.NewReader(&buf).ReadAll()
	row := records[1]
	if row[2] != "'=cmd|' /C calc'!A0" || row[6] != "'+1+1" {
		t.Errorf("cells not neutralised: %q", row)
	}
}

// Page returns real pages and the total, which is what the trail's pager
// needs: no more "older events" chain, and the last page can be computed.
func TestTrailPage(t *testing.T) {
	ctx := audit.WithActor(context.Background(), audit.Actor{UserID: 1, Email: "admin@example.com"})
	pool := dbtest.New(t)
	q := db.New(pool)
	recorder := audit.NewRecorder(q, zap.NewNop())
	trail := audit.NewTrail(q, recorder)

	for i := 0; i < 5; i++ {
		if err := recorder.Record(ctx, audit.Event{Action: audit.ActionItemView, Outcome: audit.Allowed, Kind: "ssm", Name: "/apps/a"}); err != nil {
			t.Fatal(err)
		}
	}
	first, total, err := trail.Page(ctx, audit.Filter{}, 1, 2)
	if err != nil || total != 5 || len(first) != 2 {
		t.Fatalf("page 1 = %d events of %d, err %v; want 2 of 5", len(first), total, err)
	}
	last, total, err := trail.Page(ctx, audit.Filter{}, 3, 2)
	if err != nil || total != 5 || len(last) != 1 {
		t.Fatalf("page 3 = %d events of %d, err %v; want 1 of 5", len(last), total, err)
	}
	if first[0].ID <= last[0].ID {
		t.Errorf("pages are not newest first: %d then %d", first[0].ID, last[0].ID)
	}
}
