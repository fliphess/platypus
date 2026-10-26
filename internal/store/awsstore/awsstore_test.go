package awsstore

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/smithy-go"

	"platypus/internal/sensitive"
	"platypus/internal/store"
	"platypus/internal/store/storetest"
)

// The contract tests run against a local AWS emulator (ministack in
// docker-compose and CI). Set PLATYPUS_TEST_AWS_ENDPOINT to run them.
func newTestStores(t *testing.T) (*Parameters, *Secrets) {
	t.Helper()
	endpoint := os.Getenv("PLATYPUS_TEST_AWS_ENDPOINT")
	if endpoint == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("PLATYPUS_TEST_AWS_ENDPOINT must be set in CI")
		}
		t.Skip("PLATYPUS_TEST_AWS_ENDPOINT is not set; skipping tests against the AWS emulator")
	}
	params, secrets, err := New(context.Background(), Options{TestEndpoint: endpoint})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return params, secrets
}

func TestParametersContract(t *testing.T) {
	params, _ := newTestStores(t)
	storetest.TestParameters(t, params)
}

func TestSecretsContract(t *testing.T) {
	_, secrets := newTestStores(t)
	storetest.TestSecrets(t, secrets)
}

func TestTranslateScrubsValues(t *testing.T) {
	value := sensitive.New("hunter2-secret")
	awsErr := &smithy.GenericAPIError{
		Code:    "ValidationException",
		Message: "1 validation error detected: Value 'hunter2-secret' at 'value' failed to satisfy constraint",
	}

	err := translate("update parameter", awsErr, value)
	var rejected *store.RejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("translate = %v, want a RejectedError", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaks the value: %v", err)
	}

	// Even without knowing the value, the quoted input is removed.
	err = translate("update parameter", awsErr)
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaks the echoed value: %v", err)
	}
}

func TestTranslateDropsUnknownMessages(t *testing.T) {
	err := translate("get parameter value", &smithy.GenericAPIError{Code: "SomethingNew", Message: "details with hunter2"})
	if strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "SomethingNew") {
		t.Fatalf("translate = %v, want only the code", err)
	}
}

func TestTranslateMapsCodes(t *testing.T) {
	tests := map[string]error{
		"ParameterNotFound":       store.ErrNotFound,
		"ResourceExistsException": store.ErrAlreadyExists,
		"AccessDeniedException":   store.ErrAccessDenied,
		"DecryptionFailure":       store.ErrAccessDenied,
	}
	for code, want := range tests {
		if err := translate("op", &smithy.GenericAPIError{Code: code}); !errors.Is(err, want) {
			t.Errorf("translate(%s) = %v, want %v", code, err, want)
		}
	}
}
