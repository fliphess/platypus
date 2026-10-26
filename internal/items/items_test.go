package items_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"platypus/internal/audit"
	"platypus/internal/authz"
	"platypus/internal/catalog"
	"platypus/internal/database/dbtest"
	"platypus/internal/db"
	"platypus/internal/item"
	"platypus/internal/items"
	"platypus/internal/problem"
	"platypus/internal/ratelimit"
	"platypus/internal/sensitive"
	"platypus/internal/store"
	"platypus/internal/store/memstore"
)

// The canaries are values that must never appear outside AWS.
const (
	paramCanary  = "param-canary-41b7"
	secretCanary = "secret-canary-9c2e"
)

type fixture struct {
	t       *testing.T
	svc     *items.Service
	catalog *catalog.Catalog
	params  *memstore.Parameters
	secrets *memstore.Secrets
	q       *db.Queries
	dump    func() string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pool := dbtest.New(t)
	q := db.New(pool)
	recorder := audit.NewRecorder(q, zap.NewNop())
	cat := catalog.New(q)
	params := memstore.NewParameters()
	secrets := memstore.NewSecrets()
	svc := items.NewService(cat, params, secrets, recorder, ratelimit.New(q), items.Config{
		RevealsPerMinute: 5,
		TerraformTags:    []item.Tag{{Key: "Terraform", Value: "true"}},
	})

	f := fixture{t: t, svc: svc, catalog: cat, params: params, secrets: secrets, q: q,
		dump: func() string { return dbtest.TableDump(t, pool) }}
	f.addParameter("/apps/payments/db-url", paramCanary)
	f.addParameter("/apps/payments/api-key", "key-1")
	f.addParameter("/apps/search/url", "https://search")
	f.addParameter("/other/thing", "x")
	f.addSecret("prod/payments/db", `{"user":"app","password":"`+secretCanary+`"}`)
	return f
}

func (f fixture) addParameter(name, value string) {
	f.t.Helper()
	p, err := f.params.Create(context.Background(), store.NewParameter{
		Name: name, Value: sensitive.New(value), Type: item.SSMTypeSecureString, Tier: item.SSMTierStandard,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.catalog.PutParameter(context.Background(), p, catalog.AccessOK, time.Now()); err != nil {
		f.t.Fatal(err)
	}
}

func (f fixture) addSecret(name, value string) {
	f.t.Helper()
	s, err := f.secrets.Create(context.Background(), store.NewSecret{Name: name, Value: sensitive.New(value)})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.catalog.PutSecret(context.Background(), s, catalog.AccessOK, time.Now()); err != nil {
		f.t.Fatal(err)
	}
}

func (f fixture) entry(kind item.Kind, name string) catalog.Entry {
	f.t.Helper()
	entry, found, err := f.catalog.Get(context.Background(), kind, name)
	if err != nil || !found {
		f.t.Fatalf("catalog entry %s: found=%v err=%v", name, found, err)
	}
	return entry
}

func user(ctx context.Context) context.Context {
	return audit.WithActor(ctx, audit.Actor{UserID: 42, Email: "dev@example.com"})
}

func subject(rules ...authz.Rule) authz.Subject {
	return authz.Subject{Rules: rules}
}

func rule(kind item.Kind, pattern string, perms authz.Permissions) authz.Rule {
	return authz.Rule{Kind: kind, Pattern: authz.MustParsePattern(pattern), Permissions: perms}
}

func wantProblem(t *testing.T, err error, kind problem.Kind) {
	t.Helper()
	p, ok := problem.As(err)
	if !ok || p.Kind != kind {
		t.Fatalf("err = %v, want problem kind %d", err, kind)
	}
}

func TestListShowsOnlyAllowedItems(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	dev := subject(rule(item.KindSSM, "/apps/*", authz.Permissions{List: true}))

	all, err := f.svc.List(ctx, dev, item.KindSSM, "", 1)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var names []string
	for _, it := range all.Items {
		names = append(names, it.Name)
	}
	if strings.Join(names, ",") != "/apps/payments/api-key,/apps/payments/db-url,/apps/search/url" || all.Total != 3 {
		t.Fatalf("list = %v (total %d), want the three /apps items in name order, not /other", names, all.Total)
	}
	if all.First() != 1 || all.Last() != 3 || all.HasPrevious() || all.HasNext() {
		t.Errorf("paging of a single page: first=%d last=%d", all.First(), all.Last())
	}

	found, _ := f.svc.List(ctx, dev, item.KindSSM, "SEARCH", 1)
	if len(found.Items) != 1 || found.Items[0].Name != "/apps/search/url" {
		t.Fatalf("search = %+v", found.Items)
	}
	byPath, _ := f.svc.List(ctx, dev, item.KindSSM, "payments/", 1)
	if byPath.Total != 2 {
		t.Errorf("searching a path finds %d items, want 2", byPath.Total)
	}

	// LIKE wildcards in a search are matched literally.
	if found, _ := f.svc.List(ctx, dev, item.KindSSM, "%", 1); len(found.Items) != 0 {
		t.Errorf("search for %% matched %d items", len(found.Items))
	}

	nobody, _ := f.svc.List(ctx, subject(), item.KindSSM, "", 1)
	if len(nobody.Items) != 0 {
		t.Error("a user without rules sees items")
	}
}

func TestListPages(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	for i := range items.PageSize + 5 {
		f.addParameter(fmt.Sprintf("/bulk/p%03d", i), "x")
	}
	everything := subject(rule(item.KindSSM, "/bulk/*", authz.Permissions{List: true}))

	first, _ := f.svc.List(ctx, everything, item.KindSSM, "", 1)
	second, _ := f.svc.List(ctx, everything, item.KindSSM, "", 2)
	if len(first.Items) != items.PageSize || !first.HasNext() || first.HasPrevious() {
		t.Errorf("first page: %d items, next=%v", len(first.Items), first.HasNext())
	}
	if len(second.Items) != 5 || second.HasNext() || !second.HasPrevious() || second.First() != items.PageSize+1 {
		t.Errorf("second page: %d items, first=%d", len(second.Items), second.First())
	}
	if beyond, _ := f.svc.List(ctx, everything, item.KindSSM, "", -3); beyond.Page != 1 {
		t.Errorf("a negative page should become page 1, got %d", beyond.Page)
	}
}

func TestGetHidesWhatYouCantList(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	dev := subject(rule(item.KindSSM, "/apps/*", authz.Permissions{List: true}))

	_, err := f.svc.Get(ctx, dev, item.KindSSM, "/other/thing")
	wantProblem(t, err, problem.KindNotFound)
	_, missing := f.svc.Get(ctx, dev, item.KindSSM, "/apps/does-not-exist")
	if err.Error() != missing.Error() {
		t.Errorf("hidden and missing items must look the same: %q vs %q", err, missing)
	}

	detail, err := f.svc.Get(ctx, dev, item.KindSSM, "/apps/search/url")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if detail.Permissions.Edit || detail.Permissions.Reveal || !strings.Contains(detail.Denials[authz.Reveal], "reveal") {
		t.Errorf("detail permissions = %+v, denials = %v", detail.Permissions, detail.Denials)
	}
}

func TestReveal(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	lister := subject(rule(item.KindSSM, "/apps/*", authz.Permissions{List: true}))
	revealer := subject(rule(item.KindSSM, "/apps/payments/*", authz.Permissions{Reveal: true}))

	_, err := f.svc.Reveal(ctx, lister, item.KindSSM, "/apps/payments/db-url", "")
	wantProblem(t, err, problem.KindForbidden)

	value, err := f.svc.Reveal(ctx, revealer, item.KindSSM, "/apps/payments/db-url", "")
	if err != nil || value.Reveal() != paramCanary {
		t.Fatalf("Reveal = %v, %v", value, err)
	}

	events, _ := f.q.ListAuditEvents(ctx, db.ListAuditEventsParams{MaxRows: 50})
	var reveals, denials int
	for _, e := range events {
		if e.Action == string(audit.ActionItemReveal) {
			switch e.Outcome {
			case string(audit.Allowed):
				reveals++
			case string(audit.Denied):
				denials++
			}
		}
	}
	if reveals != 1 || denials != 1 {
		t.Errorf("audit: %d reveals, %d denials; want 1 and 1", reveals, denials)
	}

	// The limit is 5 per minute in this fixture; one was used above.
	for range 4 {
		if _, err := f.svc.Reveal(ctx, revealer, item.KindSSM, "/apps/payments/db-url", ""); err != nil {
			t.Fatal(err)
		}
	}
	_, err = f.svc.Reveal(ctx, revealer, item.KindSSM, "/apps/payments/db-url", "")
	wantProblem(t, err, problem.KindTooManyRequests)
}

func TestCreate(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	creator := subject(rule(item.KindSSM, "/sandbox/*", authz.Permissions{Create: true}))

	newParam := items.NewItem{
		Kind: item.KindSSM, Name: "/sandbox/feature-flag", Value: sensitive.New("on"),
		SSMType: item.SSMTypeString, SSMTier: item.SSMTierStandard, Description: "<b>flag</b>", Team: "Payments",
	}
	if err := f.svc.Create(ctx, creator, []string{"Payments"}, newParam); err != nil {
		t.Fatalf("Create: %v", err)
	}
	tags, _ := f.params.Tags(ctx, "/sandbox/feature-flag")
	if tags["Terraform"] != "false" || tags["ManagedBy"] != "platypus" || tags["CreatedBy"] != "dev@example.com" || tags["Team"] != "Payments" {
		t.Errorf("tags = %v", tags)
	}
	if entry := f.entry(item.KindSSM, "/sandbox/feature-flag"); entry.Description != "flag" {
		t.Errorf("cached description = %q, want cleaned text", entry.Description)
	}

	// Create never overwrites.
	newParam.Value = sensitive.New("off")
	wantProblem(t, f.svc.Create(ctx, creator, []string{"Payments"}, newParam), problem.KindConflict)
	if value, _ := f.params.Value(ctx, "/sandbox/feature-flag", 0); value.Reveal() != "on" {
		t.Error("create overwrote an existing parameter")
	}

	outside := newParam
	outside.Name = "/apps/new"
	wantProblem(t, f.svc.Create(ctx, creator, nil, outside), problem.KindForbidden)

	otherTeam := newParam
	otherTeam.Name = "/sandbox/other"
	wantProblem(t, f.svc.Create(ctx, creator, []string{"Search"}, otherTeam), problem.KindInvalid)

	badJSON := items.NewItem{Kind: item.KindSSM, Name: "/sandbox/json", Value: sensitive.New("{"), IsJSON: true,
		SSMType: item.SSMTypeString, SSMTier: item.SSMTierStandard}
	wantProblem(t, f.svc.Create(ctx, creator, nil, badJSON), problem.KindInvalid)
}

func TestUpdateParameter(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	editor := subject(rule(item.KindSSM, "/apps/*", authz.Permissions{Edit: true}))
	name := "/apps/search/url"

	change := items.Change{
		Kind: item.KindSSM, Name: name, Description: "Search endpoint",
		SSMType: item.SSMTypeSecureString, SSMTier: item.SSMTierStandard, ExpectVersion: "1",
	}
	summary, err := f.svc.PreviewUpdate(ctx, editor, change)
	if err != nil {
		t.Fatalf("PreviewUpdate: %v", err)
	}
	if summary.Value != "" || len(summary.Settings) != 1 || len(summary.Warnings) == 0 {
		t.Errorf("summary = %+v, want a description change with the new-version warning", summary)
	}

	if err := f.svc.Update(ctx, editor, change); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if value, _ := f.params.Value(ctx, name, 0); value.Reveal() != "https://search" {
		t.Errorf("a description change altered the value to %q", value.Reveal())
	}
	if entry := f.entry(item.KindSSM, name); entry.SSMVersion != 2 || entry.Description != "Search endpoint" {
		t.Errorf("cache not refreshed: %+v", entry)
	}

	// The same form submitted again is outdated now.
	newValue := sensitive.New("https://search-v2")
	change.Value = &newValue
	wantProblem(t, f.svc.Update(ctx, editor, change), problem.KindConflict)

	change.ExpectVersion = "2"
	if err := f.svc.Update(ctx, editor, change); err != nil {
		t.Fatalf("Update value: %v", err)
	}

	// Nothing changed: refused.
	unchanged := items.Change{Kind: item.KindSSM, Name: name, Description: "Search endpoint",
		SSMType: item.SSMTypeSecureString, SSMTier: item.SSMTierStandard, ExpectVersion: "3"}
	wantProblem(t, f.svc.Update(ctx, editor, unchanged), problem.KindInvalid)

	lister := subject(rule(item.KindSSM, "/apps/*", authz.Permissions{List: true}))
	wantProblem(t, f.svc.Update(ctx, lister, change), problem.KindForbidden)
}

func TestPreviewShowsJSONKeysOnlyToRevealers(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	name := "prod/payments/db"
	newValue := sensitive.New(`{"user":"app","password":"new","host":"db"}`)
	change := items.Change{Kind: item.KindSecret, Name: name, Value: &newValue, IsJSON: true,
		ExpectVersion: f.entry(item.KindSecret, name).Version()}

	editOnly := subject(rule(item.KindSecret, "prod/*", authz.Permissions{Edit: true}))
	summary, err := f.svc.PreviewUpdate(ctx, editOnly, change)
	if err != nil {
		t.Fatalf("PreviewUpdate: %v", err)
	}
	if summary.JSONKeys != nil || summary.Value != "replaced" {
		t.Errorf("edit-only summary = %+v; must not show keys", summary)
	}

	full := subject(rule(item.KindSecret, "prod/*", authz.Permissions{Edit: true, Reveal: true}))
	summary, _ = f.svc.PreviewUpdate(ctx, full, change)
	if summary.JSONKeys == nil || strings.Join(summary.JSONKeys.Added, ",") != "host" || strings.Join(summary.JSONKeys.Changed, ",") != "password" {
		t.Errorf("JSON keys = %+v", summary.JSONKeys)
	}
}

func TestRollback(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	editor := subject(
		rule(item.KindSSM, "/apps/*", authz.Permissions{Edit: true}),
		rule(item.KindSecret, "prod/*", authz.Permissions{Edit: true}),
	)

	newValue := sensitive.New("key-2")
	if err := f.svc.Update(ctx, editor, items.Change{Kind: item.KindSSM, Name: "/apps/payments/api-key", Value: &newValue,
		SSMType: item.SSMTypeSecureString, SSMTier: item.SSMTierStandard, ExpectVersion: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Rollback(ctx, editor, item.KindSSM, "/apps/payments/api-key", "1", "2"); err != nil {
		t.Fatalf("Rollback parameter: %v", err)
	}
	if value, _ := f.params.Value(ctx, "/apps/payments/api-key", 0); value.Reveal() != "key-1" {
		t.Errorf("after rollback value = %q", value.Reveal())
	}

	first := f.entry(item.KindSecret, "prod/payments/db").Version()
	secretValue := sensitive.New(`{"user":"app","password":"rotated"}`)
	if err := f.svc.Update(ctx, editor, items.Change{Kind: item.KindSecret, Name: "prod/payments/db", Value: &secretValue,
		IsJSON: true, ExpectVersion: first}); err != nil {
		t.Fatal(err)
	}
	second := f.entry(item.KindSecret, "prod/payments/db").Version()
	if err := f.svc.Rollback(ctx, editor, item.KindSecret, "prod/payments/db", first, second); err != nil {
		t.Fatalf("Rollback secret: %v", err)
	}
	if f.entry(item.KindSecret, "prod/payments/db").Version() != first {
		t.Error("secret rollback didn't make the first version current")
	}
}

func TestAccessDeniedHidesTheItem(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	revealer := subject(rule(item.KindSSM, "/apps/*", authz.Permissions{Reveal: true}))
	f.params.Deny("/apps/payments/db-url")

	_, err := f.svc.Reveal(ctx, revealer, item.KindSSM, "/apps/payments/db-url", "")
	wantProblem(t, err, problem.KindNotFound)

	listing, _ := f.svc.List(ctx, revealer, item.KindSSM, "", 1)
	for _, s := range listing.Items {
		if s.Name == "/apps/payments/db-url" {
			t.Fatal("an item AWS denies platypus is still listed")
		}
	}
}

func TestBinarySecretsAreNotOverwritten(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	f.addSecret("prod/binary", "x")
	f.secrets.MarkBinary("prod/binary")
	editor := subject(rule(item.KindSecret, "prod/*", authz.Permissions{Edit: true, Reveal: true}))

	value := sensitive.New("text")
	err := f.svc.Update(ctx, editor, items.Change{Kind: item.KindSecret, Name: "prod/binary", Value: &value,
		ExpectVersion: f.entry(item.KindSecret, "prod/binary").Version()})
	wantProblem(t, err, problem.KindInvalid)

	_, err = f.svc.Reveal(ctx, editor, item.KindSecret, "prod/binary", "")
	if p, ok := problem.As(err); !ok || !strings.Contains(p.Message, "binary") {
		t.Errorf("reveal of a binary secret: %v", err)
	}
}

func TestNotes(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	editor := subject(rule(item.KindSSM, "/apps/*", authz.Permissions{Edit: true}))
	lister := subject(rule(item.KindSSM, "/apps/*", authz.Permissions{List: true}))

	if err := f.svc.SaveNote(ctx, editor, item.KindSSM, "/apps/search/url", "DO NOT CHANGE <script>x</script>"); err != nil {
		t.Fatalf("SaveNote: %v", err)
	}
	detail, _ := f.svc.Get(ctx, lister, item.KindSSM, "/apps/search/url")
	if detail.Note == nil || detail.Note.Body != "DO NOT CHANGE" || detail.Note.UpdatedBy != "dev@example.com" {
		t.Fatalf("note = %+v", detail.Note)
	}
	found, _ := f.svc.List(ctx, lister, item.KindSSM, "do not change", 1)
	if len(found.Items) != 1 || !found.Items[0].HasNote {
		t.Errorf("search on note text = %+v", found.Items)
	}
	wantProblem(t, f.svc.SaveNote(ctx, lister, item.KindSSM, "/apps/search/url", "x"), problem.KindForbidden)
}

// After every kind of operation, no value may be stored anywhere in the database.
func TestValuesNeverReachTheDatabase(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	all := subject(
		rule(item.KindSSM, "*", authz.Permissions{List: true, Create: true, Edit: true, Reveal: true}),
		rule(item.KindSecret, "*", authz.Permissions{List: true, Create: true, Edit: true, Reveal: true}),
	)

	run := func(err error) {
		t.Helper()
		if err != nil && !errors.As(err, new(*problem.Problem)) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	_, err := f.svc.Reveal(ctx, all, item.KindSSM, "/apps/payments/db-url", "")
	run(err)
	_, err = f.svc.Reveal(ctx, all, item.KindSecret, "prod/payments/db", "")
	run(err)
	_, err = f.svc.RevealForEditing(ctx, all, item.KindSecret, "prod/payments/db")
	run(err)

	canaryValue := sensitive.New(`{"password":"` + secretCanary + `-new"}`)
	change := items.Change{Kind: item.KindSecret, Name: "prod/payments/db", Value: &canaryValue, IsJSON: true,
		ExpectVersion: f.entry(item.KindSecret, "prod/payments/db").Version()}
	_, err = f.svc.PreviewUpdate(ctx, all, change)
	run(err)
	run(f.svc.Update(ctx, all, change))

	run(f.svc.Create(ctx, all, nil, items.NewItem{Kind: item.KindSSM, Name: "/new/one", Value: sensitive.New(paramCanary + "-created"),
		SSMType: item.SSMTypeSecureString, SSMTier: item.SSMTierStandard}))
	// A value that is too large is refused; the error must not echo it.
	huge := sensitive.New(paramCanary + strings.Repeat("x", 5000))
	run(f.svc.Create(ctx, all, nil, items.NewItem{Kind: item.KindSSM, Name: "/new/huge", Value: huge,
		SSMType: item.SSMTypeSecureString, SSMTier: item.SSMTierStandard}))

	dump := f.dump()
	for _, canary := range []string{paramCanary, secretCanary} {
		if strings.Contains(dump, canary) {
			t.Fatalf("a value reached the database:\n%s", dump)
		}
	}
}

func TestTerraformManagedItemsCantBeChanged(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	editor := subject(
		rule(item.KindSecret, "*", authz.Permissions{Edit: true, Reveal: true}),
		rule(item.KindSSM, "*", authz.Permissions{Edit: true, Reveal: true}),
	)

	sec, err := f.secrets.Create(ctx, store.NewSecret{Name: "prod/tf", Value: sensitive.New("v1"), Tags: map[string]string{"Terraform": "True"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.catalog.PutSecret(ctx, sec, catalog.AccessOK, time.Now()); err != nil {
		t.Fatal(err)
	}
	// SSM tags are only known after a fetch; the check fetches them itself.
	p, err := f.params.Create(ctx, store.NewParameter{Name: "/tf/param", Value: sensitive.New("v1"), Type: "String",
		Tier: "Standard", Tags: map[string]string{"Terraform": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.catalog.PutParameter(ctx, p, catalog.AccessOK, time.Now()); err != nil {
		t.Fatal(err)
	}

	value := sensitive.New("v2")
	err = f.svc.Update(ctx, editor, items.Change{Kind: item.KindSSM, Name: "/tf/param", Value: &value,
		SSMType: "String", SSMTier: "Standard", ExpectVersion: "1"})
	wantProblem(t, err, problem.KindForbidden)
	if !strings.Contains(err.Error(), "Terraform") {
		t.Errorf("the refusal should point to Terraform: %v", err)
	}
	err = f.svc.Update(ctx, editor, items.Change{Kind: item.KindSecret, Name: "prod/tf", Value: &value, ExpectVersion: sec.CurrentVersionID})
	wantProblem(t, err, problem.KindForbidden)
	wantProblem(t, f.svc.Rollback(ctx, editor, item.KindSecret, "prod/tf", sec.CurrentVersionID, sec.CurrentVersionID), problem.KindForbidden)

	detail, _ := f.svc.Get(ctx, editor, item.KindSecret, "prod/tf")
	if !detail.TerraformManaged || detail.TerraformReason == "" {
		t.Errorf("detail = %+v, want it marked as managed by Terraform", detail.TerraformManaged)
	}
	listing, _ := f.svc.List(ctx, editor, item.KindSecret, "prod/tf", 1)
	if len(listing.Items) != 1 || !listing.Items[0].TerraformManaged {
		t.Error("the list should mark the secret as managed by Terraform")
	}

	// Notes stay possible, and items without the tag can still be changed.
	if err := f.svc.SaveNote(ctx, editor, item.KindSecret, "prod/tf", "Owned by the platform team"); err != nil {
		t.Errorf("a note on a Terraform item: %v", err)
	}
	if v, _ := f.secrets.Value(ctx, "prod/tf", ""); v.Reveal() != "v1" {
		t.Error("the Terraform-managed secret changed")
	}
}

// Every Service method refuses a subject without the permission it needs,
// and AWS stays untouched. A new method belongs in this table.
func TestEveryMethodDeniesByDefault(t *testing.T) {
	f := newFixture(t)
	ctx := user(context.Background())
	const param = "/apps/payments/api-key"
	const secret = "prod/payments/db"
	paramBefore := f.entry(item.KindSSM, param)
	secretBefore := f.entry(item.KindSecret, secret)
	newValue := sensitive.New("new-value")

	everything := authz.Permissions{List: true, Create: true, Edit: true, Reveal: true}
	subjects := map[string]authz.Subject{
		"no rules": subject(),
		"list only": subject(rule(item.KindSSM, "*", authz.Permissions{List: true}),
			rule(item.KindSecret, "*", authz.Permissions{List: true})),
		"other kind": subject(rule(item.KindSSM, "prod/*", everything), rule(item.KindSecret, "/apps/*", everything)),
		"blocked": {Blocked: true, Rules: []authz.Rule{rule(item.KindSSM, "*", everything),
			rule(item.KindSecret, "*", everything)}},
	}
	calls := []struct {
		name string
		// listAllows: a list-only subject may do this.
		listAllows bool
		call       func(authz.Subject) error
	}{
		{"Get", true, func(s authz.Subject) error {
			_, err := f.svc.Get(ctx, s, item.KindSSM, param)
			return err
		}},
		{"History", true, func(s authz.Subject) error {
			_, err := f.svc.History(ctx, s, item.KindSecret, secret)
			return err
		}},
		{"Reveal", false, func(s authz.Subject) error {
			_, err := f.svc.Reveal(ctx, s, item.KindSSM, param, "")
			return err
		}},
		{"RevealForEditing", false, func(s authz.Subject) error {
			_, err := f.svc.RevealForEditing(ctx, s, item.KindSecret, secret)
			return err
		}},
		{"PreviewCreate", false, func(s authz.Subject) error {
			_, err := f.svc.PreviewCreate(ctx, s, nil, items.NewItem{Kind: item.KindSSM, Name: "/apps/new",
				Value: newValue, SSMType: item.SSMTypeSecureString, SSMTier: item.SSMTierStandard})
			return err
		}},
		{"Create", false, func(s authz.Subject) error {
			return f.svc.Create(ctx, s, nil, items.NewItem{Kind: item.KindSecret, Name: "prod/new", Value: newValue})
		}},
		{"PreviewUpdate", false, func(s authz.Subject) error {
			_, err := f.svc.PreviewUpdate(ctx, s, items.Change{Kind: item.KindSSM, Name: param, Value: &newValue,
				SSMType: paramBefore.SSMType, SSMTier: paramBefore.SSMTier, ExpectVersion: "1"})
			return err
		}},
		{"Update", false, func(s authz.Subject) error {
			return f.svc.Update(ctx, s, items.Change{Kind: item.KindSecret, Name: secret, Value: &newValue,
				ExpectVersion: secretBefore.SecretVersionID})
		}},
		{"Rollback", false, func(s authz.Subject) error {
			return f.svc.Rollback(ctx, s, item.KindSSM, param, "1", "1")
		}},
		{"SaveNote", false, func(s authz.Subject) error {
			return f.svc.SaveNote(ctx, s, item.KindSecret, secret, "a note")
		}},
	}

	for subjectName, s := range subjects {
		for _, c := range calls {
			if subjectName == "list only" && c.listAllows {
				continue
			}
			err := c.call(s)
			p, ok := problem.As(err)
			if !ok || (p.Kind != problem.KindNotFound && p.Kind != problem.KindForbidden) {
				t.Errorf("%s as %q: err = %v, want not found or forbidden", c.name, subjectName, err)
			}
		}
		listing, err := f.svc.List(ctx, s, item.KindSecret, "", 1)
		if err != nil || (subjectName != "list only" && len(listing.Items) != 0) {
			t.Errorf("List as %q = %d items, %v", subjectName, len(listing.Items), err)
		}
	}

	if after := f.entry(item.KindSSM, param); after.SSMVersion != paramBefore.SSMVersion {
		t.Errorf("parameter changed: version %d -> %d", paramBefore.SSMVersion, after.SSMVersion)
	}
	if after := f.entry(item.KindSecret, secret); after.SecretVersionID != secretBefore.SecretVersionID {
		t.Error("secret changed")
	}
	if _, err := f.params.Describe(context.Background(), "/apps/new"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("parameter created: %v", err)
	}
	if _, err := f.secrets.Describe(context.Background(), "prod/new"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("secret created: %v", err)
	}
	if note, _ := f.catalog.Note(context.Background(), item.KindSecret, secret); note != nil {
		t.Error("note saved")
	}
}
