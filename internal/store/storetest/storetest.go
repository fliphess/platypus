// Package storetest holds the contract every store implementation must meet.
// The in-memory fake and the AWS implementation (against a local emulator)
// both run it, so tests that use the fake can trust it behaves like AWS.
package storetest

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"platypus/internal/item"
	"platypus/internal/sensitive"
	"platypus/internal/store"
)

// uniqueName returns a name no other test run uses, so suites can share an
// emulator without cleaning up.
func uniqueName(prefix string) string {
	return prefix + rand.Text()
}

// ParameterStore is a parameter store that also writes the bootstrap token;
// both implementations are.
type ParameterStore interface {
	store.Parameters
	store.TokenWriter
}

// TestParameters runs the parameter contract against p.
func TestParameters(t *testing.T, p ParameterStore) {
	ctx := context.Background()

	t.Run("create, describe and read", func(t *testing.T) {
		name := uniqueName("/storetest/create/")
		created, err := p.Create(ctx, store.NewParameter{
			Name:        name,
			Value:       sensitive.New("first"),
			Type:        item.SSMTypeSecureString,
			Tier:        item.SSMTierStandard,
			Description: "a test parameter",
			Tags:        map[string]string{"Terraform": "false"},
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if created.Version != 1 || created.Type != item.SSMTypeSecureString || created.Description != "a test parameter" {
			t.Errorf("Create returned %+v", created)
		}

		described, err := p.Describe(ctx, name)
		if err != nil || described.Version != 1 {
			t.Fatalf("Describe = %+v, %v", described, err)
		}

		value, err := p.Value(ctx, name, 0)
		if err != nil || value.Reveal() != "first" {
			t.Fatalf("Value = %q, %v", value.Reveal(), err)
		}

		tags, err := p.Tags(ctx, name)
		if err != nil || tags["Terraform"] != "false" {
			t.Fatalf("Tags = %v, %v", tags, err)
		}

		if err := p.CheckAccess(ctx, name); err != nil {
			t.Fatalf("CheckAccess: %v", err)
		}
	})

	t.Run("create never overwrites", func(t *testing.T) {
		name := uniqueName("/storetest/exists/")
		mustCreateParameter(t, p, name, "original")
		_, err := p.Create(ctx, store.NewParameter{Name: name, Value: sensitive.New("other"), Type: item.SSMTypeString, Tier: item.SSMTierStandard})
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Fatalf("second Create error = %v, want ErrAlreadyExists", err)
		}
		if value, _ := p.Value(ctx, name, 0); value.Reveal() != "original" {
			t.Fatalf("value changed to %q", value.Reveal())
		}
	})

	t.Run("update, history and old versions", func(t *testing.T) {
		name := uniqueName("/storetest/update/")
		mustCreateParameter(t, p, name, "v1")

		updated, err := p.Update(ctx, store.ParameterUpdate{
			Name: name, Value: sensitive.New("v2"), Type: item.SSMTypeSecureString,
			Tier: item.SSMTierStandard, Description: "changed", ExpectVersion: 1,
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if updated.Version != 2 || updated.Description != "changed" {
			t.Errorf("Update returned %+v", updated)
		}

		if value, _ := p.Value(ctx, name, 1); value.Reveal() != "v1" {
			t.Errorf("version 1 = %q", value.Reveal())
		}
		if value, _ := p.Value(ctx, name, 0); value.Reveal() != "v2" {
			t.Errorf("current = %q", value.Reveal())
		}

		history, err := p.History(ctx, name)
		if err != nil || len(history) != 2 || history[0].Version != 2 || history[1].Version != 1 {
			t.Fatalf("History = %+v, %v (want newest first)", history, err)
		}
	})

	t.Run("update detects conflicts", func(t *testing.T) {
		name := uniqueName("/storetest/conflict/")
		mustCreateParameter(t, p, name, "v1")
		_, err := p.Update(ctx, store.ParameterUpdate{
			Name: name, Value: sensitive.New("v2"), Type: item.SSMTypeSecureString,
			Tier: item.SSMTierStandard, ExpectVersion: 7,
		})
		if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("Update error = %v, want ErrConflict", err)
		}
	})

	t.Run("missing parameters", func(t *testing.T) {
		name := uniqueName("/storetest/missing/")
		if _, err := p.Describe(ctx, name); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Describe error = %v", err)
		}
		if _, err := p.Value(ctx, name, 0); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Value error = %v", err)
		}
		if err := p.CheckAccess(ctx, name); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("CheckAccess error = %v", err)
		}
	})

	t.Run("write creates and overwrites", func(t *testing.T) {
		name := uniqueName("/storetest/write/")
		for _, v := range []string{"one", "two"} {
			if err := p.Write(ctx, name, sensitive.New(v), "bootstrap token"); err != nil {
				t.Fatalf("Write(%s): %v", v, err)
			}
		}
		if value, _ := p.Value(ctx, name, 0); value.Reveal() != "two" {
			t.Fatalf("value = %q", value.Reveal())
		}
	})

	t.Run("list includes created parameters", func(t *testing.T) {
		name := uniqueName("/storetest/list/")
		mustCreateParameter(t, p, name, "x")
		found := false
		err := p.List(ctx, func(param store.Parameter) error {
			found = found || param.Name == name
			return nil
		})
		if err != nil || !found {
			t.Fatalf("List: found=%v err=%v", found, err)
		}
	})
}

func mustCreateParameter(t *testing.T, p store.Parameters, name, value string) {
	t.Helper()
	_, err := p.Create(context.Background(), store.NewParameter{
		Name: name, Value: sensitive.New(value), Type: item.SSMTypeSecureString, Tier: item.SSMTierStandard,
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", name, err)
	}
}

// TestSecrets runs the secret contract against s.
func TestSecrets(t *testing.T, s store.Secrets) {
	ctx := context.Background()

	t.Run("create, describe and read", func(t *testing.T) {
		name := uniqueName("storetest/create/")
		created, err := s.Create(ctx, store.NewSecret{
			Name:        name,
			Value:       sensitive.New(`{"user":"app"}`),
			Description: "a test secret",
			Tags:        map[string]string{"Terraform": "false"},
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if created.CurrentVersionID == "" || created.Description != "a test secret" || created.Tags["Terraform"] != "false" {
			t.Errorf("Create returned %+v", created)
		}
		value, err := s.Value(ctx, name, "")
		if err != nil || value.Reveal() != `{"user":"app"}` {
			t.Fatalf("Value = %q, %v", value.Reveal(), err)
		}
		if err := s.CheckAccess(ctx, name); err != nil {
			t.Fatalf("CheckAccess: %v", err)
		}
	})

	t.Run("create never overwrites", func(t *testing.T) {
		name := uniqueName("storetest/exists/")
		mustCreateSecret(t, s, name, "original")
		if _, err := s.Create(ctx, store.NewSecret{Name: name, Value: sensitive.New("other")}); !errors.Is(err, store.ErrAlreadyExists) {
			t.Fatalf("second Create error = %v, want ErrAlreadyExists", err)
		}
	})

	t.Run("put value, versions and restore", func(t *testing.T) {
		name := uniqueName("storetest/versions/")
		first := mustCreateSecret(t, s, name, "v1")

		second, err := s.PutValue(ctx, name, sensitive.New("v2"), first.CurrentVersionID)
		if err != nil {
			t.Fatalf("PutValue: %v", err)
		}
		if second.CurrentVersionID == first.CurrentVersionID {
			t.Fatal("PutValue didn't create a new version")
		}
		if value, _ := s.Value(ctx, name, first.CurrentVersionID); value.Reveal() != "v1" {
			t.Errorf("old version = %q", value.Reveal())
		}

		versions, err := s.Versions(ctx, name)
		if err != nil || len(versions) != 2 {
			t.Fatalf("Versions = %+v, %v", versions, err)
		}
		currentCount := 0
		for _, v := range versions {
			if v.IsCurrent() {
				currentCount++
				if v.ID != second.CurrentVersionID {
					t.Errorf("current version = %s, want %s", v.ID, second.CurrentVersionID)
				}
			}
		}
		if currentCount != 1 {
			t.Errorf("%d current versions", currentCount)
		}

		if err := s.Restore(ctx, name, first.CurrentVersionID, second.CurrentVersionID); err != nil {
			t.Fatalf("Restore: %v", err)
		}
		if value, _ := s.Value(ctx, name, ""); value.Reveal() != "v1" {
			t.Errorf("after restore current = %q", value.Reveal())
		}
	})

	t.Run("conflicts", func(t *testing.T) {
		name := uniqueName("storetest/conflict/")
		mustCreateSecret(t, s, name, "v1")
		if _, err := s.PutValue(ctx, name, sensitive.New("v2"), "stale-version"); !errors.Is(err, store.ErrConflict) {
			t.Errorf("PutValue error = %v, want ErrConflict", err)
		}
		if err := s.Restore(ctx, name, "any", "stale-version"); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Restore error = %v, want ErrConflict", err)
		}
	})

	t.Run("update description", func(t *testing.T) {
		name := uniqueName("storetest/description/")
		created := mustCreateSecret(t, s, name, "v1")
		if err := s.UpdateDescription(ctx, name, "stale", "stale-version"); !errors.Is(err, store.ErrConflict) {
			t.Errorf("UpdateDescription with a stale version: %v, want ErrConflict", err)
		}
		if err := s.UpdateDescription(ctx, name, "new description", created.CurrentVersionID); err != nil {
			t.Fatalf("UpdateDescription: %v", err)
		}
		described, err := s.Describe(ctx, name)
		if err != nil || described.Description != "new description" || described.CurrentVersionID != created.CurrentVersionID {
			t.Fatalf("Describe = %+v, %v", described, err)
		}
	})

	t.Run("missing secrets", func(t *testing.T) {
		name := uniqueName("storetest/missing/")
		if _, err := s.Describe(ctx, name); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Describe error = %v", err)
		}
		if _, err := s.Value(ctx, name, ""); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Value error = %v", err)
		}
	})

	t.Run("list includes created secrets", func(t *testing.T) {
		name := uniqueName("storetest/list/")
		mustCreateSecret(t, s, name, "x")
		found := false
		err := s.List(ctx, func(secret store.Secret) error {
			found = found || secret.Name == name
			return nil
		})
		if err != nil || !found {
			t.Fatalf("List: found=%v err=%v", found, err)
		}
	})
}

func mustCreateSecret(t *testing.T, s store.Secrets, name, value string) store.Secret {
	t.Helper()
	secret, err := s.Create(context.Background(), store.NewSecret{Name: name, Value: sensitive.New(value)})
	if err != nil {
		t.Fatalf("Create(%s): %v", name, err)
	}
	return secret
}
