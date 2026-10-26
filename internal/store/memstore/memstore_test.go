package memstore

import (
	"context"
	"errors"
	"testing"

	"platypus/internal/sensitive"
	"platypus/internal/store"
	"platypus/internal/store/storetest"
)

func TestParametersContract(t *testing.T) {
	storetest.TestParameters(t, NewParameters())
}

func TestSecretsContract(t *testing.T) {
	storetest.TestSecrets(t, NewSecrets())
}

func TestDenyAndBinary(t *testing.T) {
	ctx := context.Background()

	params := NewParameters()
	_, _ = params.Create(ctx, store.NewParameter{Name: "/denied", Value: sensitive.New("x"), Type: "String", Tier: "Standard"})
	params.Deny("/denied")
	if err := params.CheckAccess(ctx, "/denied"); !errors.Is(err, store.ErrAccessDenied) {
		t.Errorf("CheckAccess = %v", err)
	}
	if _, err := params.Value(ctx, "/denied", 0); !errors.Is(err, store.ErrAccessDenied) {
		t.Errorf("Value = %v", err)
	}

	secrets := NewSecrets()
	_, _ = secrets.Create(ctx, store.NewSecret{Name: "binary", Value: sensitive.New("x")})
	secrets.MarkBinary("binary")
	if _, err := secrets.Value(ctx, "binary", ""); !errors.Is(err, store.ErrBinaryValue) {
		t.Errorf("Value = %v", err)
	}
}
