// Package dbtest gives tests a fresh, migrated Postgres database.
//
// Set PLATYPUS_TEST_DATABASE_URL to a superuser connection URL, for example
// postgres://postgres:postgres@localhost:55432/postgres (docker-compose).
// Without it, database tests are skipped locally and fail in CI, so they can't
// silently stop running there.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// New creates a database for one test, applies the Flyway migrations to it
// and drops it when the test ends.
func New(t testing.TB) *pgxpool.Pool {
	t.Helper()
	adminURL := os.Getenv("PLATYPUS_TEST_DATABASE_URL")
	if adminURL == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("PLATYPUS_TEST_DATABASE_URL must be set in CI")
		}
		t.Skip("PLATYPUS_TEST_DATABASE_URL is not set; skipping database test")
	}
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect to test Postgres: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()

	name := "platypus_test_" + randomSuffix()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create test database: %v", err)
	}

	config, err := pgxpool.ParseConfig(adminURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	config.ConnConfig.Database = name
	config.ConnConfig.RuntimeParams["search_path"] = "platypus"

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		dropCtx := context.Background()
		admin, err := pgx.Connect(dropCtx, adminURL)
		if err != nil {
			return
		}
		defer func() { _ = admin.Close(dropCtx) }()
		_, _ = admin.Exec(dropCtx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})

	migrate(t, pool)
	return pool
}

// migrate applies the versioned migrations in Flyway order, the way Flyway
// does in docker-compose and CI.
func migrate(t testing.TB, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "CREATE SCHEMA platypus"); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	migrations := os.DirFS(migrationsDir())
	for _, name := range migrationFiles(t, migrations) {
		sql, err := fs.ReadFile(migrations, name)
		if err != nil {
			t.Fatalf("read migration: %v", err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}

var versionedMigration = regexp.MustCompile(`^V([0-9.]+)__.+\.sql$`)

// migrationsDir is database/migrations/updates in the repository.
func migrationsDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "database", "migrations", "updates")
}

// migrationFiles returns the versioned migrations in Flyway order.
func migrationFiles(t testing.TB, migrations fs.FS) []string {
	t.Helper()
	entries, err := fs.ReadDir(migrations, ".")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}

	type migration struct {
		version []int
		name    string
	}
	var found []migration
	for _, entry := range entries {
		match := versionedMigration.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		var version []int
		for part := range strings.SplitSeq(match[1], ".") {
			n, _ := strconv.Atoi(part)
			version = append(version, n)
		}
		found = append(found, migration{version: version, name: entry.Name()})
	}
	slices.SortFunc(found, func(a, b migration) int { return slices.Compare(a.version, b.version) })

	names := make([]string, len(found))
	for i, m := range found {
		names[i] = m.name
	}
	if len(names) == 0 {
		t.Fatal("no migrations found")
	}
	return names
}

func randomSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// TableDump returns every row of every platypus table as text. Leak tests
// search it for values that must never be stored.
func TableDump(t testing.TB, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	rows, err := pool.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'platypus' ORDER BY tablename`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}

	var dump strings.Builder
	for _, table := range tables {
		rows, err := pool.Query(ctx, fmt.Sprintf(`SELECT t::text FROM platypus.%s AS t`, pgx.Identifier{table}.Sanitize()))
		if err != nil {
			t.Fatalf("dump %s: %v", table, err)
		}
		lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("dump %s: %v", table, err)
		}
		for _, line := range lines {
			dump.WriteString(table + ": " + line + "\n")
		}
	}
	return dump.String()
}
