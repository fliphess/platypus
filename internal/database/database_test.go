package database_test

import (
	"context"
	"errors"
	"testing"

	"platypus/internal/database"
	"platypus/internal/database/dbtest"
	"platypus/internal/db"
)

func TestMigrationsAndInTx(t *testing.T) {
	pool := dbtest.New(t)
	ctx := context.Background()

	state, err := db.New(pool).GetAppState(ctx)
	if err != nil {
		t.Fatalf("GetAppState: %v", err)
	}
	if state.Bootstrapped {
		t.Fatal("a fresh database must not be bootstrapped")
	}

	// A failing transaction leaves nothing behind.
	err = database.InTx(ctx, pool, func(q *db.Queries) error {
		if err := q.SetBootstrapped(ctx, true); err != nil {
			return err
		}
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("InTx error = %v", err)
	}
	if state, _ := db.New(pool).GetAppState(ctx); state.Bootstrapped {
		t.Fatal("rolled-back change is visible")
	}
}
