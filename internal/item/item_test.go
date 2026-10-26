package item

import (
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	tests := []struct {
		kind    Kind
		name    string
		wantErr string
	}{
		{KindSSM, "/apps/payments/db-url", ""},
		{KindSSM, "simple_name.v2", ""},
		{KindSSM, "", "can't be empty"},
		{KindSSM, "apps/payments", "must start with /"},
		{KindSSM, "/apps/", "can't end with /"},
		{KindSSM, "/apps//x", "empty path segments"},
		{KindSSM, "/aws/reserved", `can't start with "aws"`},
		{KindSSM, "ssm-thing", `can't start with "aws" or "ssm"`},
		{KindSSM, "/apps/with space", "may only contain"},
		{KindSSM, "/" + strings.Repeat("a/", 16) + "x", "15 levels"},
		{KindSecret, "prod/payments/db", ""},
		{KindSecret, "user+tag=x@y.z", ""},
		{KindSecret, "with space", "may only contain"},
		{KindSecret, strings.Repeat("a", 513), "at most 512"},
		{Kind("other"), "x", "unknown item kind"},
	}
	for _, tt := range tests {
		err := ValidateName(tt.kind, tt.name)
		if tt.wantErr == "" && err != nil {
			t.Errorf("ValidateName(%s, %q) error: %v", tt.kind, tt.name, err)
		}
		if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
			t.Errorf("ValidateName(%s, %q) error = %v, want %q", tt.kind, tt.name, err, tt.wantErr)
		}
	}
}

func TestParseKind(t *testing.T) {
	for _, k := range Kinds {
		if got, err := ParseKind(string(k)); err != nil || got != k {
			t.Errorf("ParseKind(%q) = %q, %v", k, got, err)
		}
	}
	if _, err := ParseKind("parameter"); err == nil {
		t.Error("ParseKind should reject unknown kinds")
	}
}

func TestMaxValueBytes(t *testing.T) {
	if MaxValueBytes(KindSSM, SSMTierStandard) != 4096 ||
		MaxValueBytes(KindSSM, SSMTierAdvanced) != 8192 ||
		MaxValueBytes(KindSecret, "") != 65536 {
		t.Error("MaxValueBytes doesn't match the AWS limits")
	}
}

// Tag matching is forgiving about case, so a hand-written tag still protects
// an item Terraform manages.
func TestHasAnyTag(t *testing.T) {
	wanted := []Tag{{Key: "Terraform", Value: "true"}}
	for name, tags := range map[string]map[string]string{
		"exact":         {"Terraform": "true"},
		"key and value": {"terraform": "TRUE"},
		"value only":    {"Terraform": "True"},
		"key only":      {"TERRAFORM": "true"},
	} {
		if !HasAnyTag(tags, wanted) {
			t.Errorf("%s: %v does not match %v", name, tags, wanted)
		}
	}
	for name, tags := range map[string]map[string]string{
		"other value": {"Terraform": "false"},
		"other key":   {"ManagedBy": "Terraform"},
		"empty":       {},
	} {
		if HasAnyTag(tags, wanted) {
			t.Errorf("%s: %v unexpectedly matches %v", name, tags, wanted)
		}
	}
}
