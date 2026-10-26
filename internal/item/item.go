// Package item defines what platypus manages: SSM parameters and Secrets
// Manager secrets, both called items. It holds the shared vocabulary only;
// talking to AWS lives in package store.
package item

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Kind is the type of an item.
type Kind string

const (
	KindSSM    Kind = "ssm"
	KindSecret Kind = "secret"
)

// Kinds lists all kinds in display order.
var Kinds = []Kind{KindSSM, KindSecret}

// ParseKind converts text from a URL or form into a Kind.
func ParseKind(s string) (Kind, error) {
	switch Kind(s) {
	case KindSSM, KindSecret:
		return Kind(s), nil
	}
	return "", fmt.Errorf("unknown item kind %q", s)
}

// Noun is the human name for one item of this kind.
func (k Kind) Noun() string {
	if k == KindSecret {
		return "secret"
	}
	return "parameter"
}

// PluralNoun is the human name for several items of this kind.
func (k Kind) PluralNoun() string {
	return k.Noun() + "s"
}

// Title is the name of the kind as shown in tabs and headings.
func (k Kind) Title() string {
	if k == KindSecret {
		return "Secrets"
	}
	return "SSM parameters"
}

var (
	ssmNamePattern    = regexp.MustCompile(`^[a-zA-Z0-9_.\-/]+$`)
	secretNamePattern = regexp.MustCompile(`^[a-zA-Z0-9/_+=.@\-]+$`)
)

// ValidateName checks a name for a new item against the AWS naming rules, so
// users get a clear message instead of an AWS error.
func ValidateName(kind Kind, name string) error {
	if name == "" {
		return errors.New("the name can't be empty")
	}
	switch kind {
	case KindSSM:
		lower := strings.ToLower(strings.TrimPrefix(name, "/"))
		switch {
		case len(name) > 2048:
			return errors.New("the name can be at most 2048 characters")
		case !ssmNamePattern.MatchString(name):
			return errors.New("the name may only contain letters, digits and _ . - /")
		case strings.Contains(name, "/") && !strings.HasPrefix(name, "/"):
			return errors.New("a name with a path must start with /")
		case strings.HasSuffix(name, "/") || strings.Contains(name, "//"):
			return errors.New("the name can't end with / or contain empty path segments")
		case strings.HasPrefix(lower, "aws") || strings.HasPrefix(lower, "ssm"):
			return errors.New(`the name can't start with "aws" or "ssm"`)
		case strings.Count(name, "/") > 15:
			return errors.New("the name can be at most 15 levels deep")
		}
	case KindSecret:
		switch {
		case len(name) > 512:
			return errors.New("the name can be at most 512 characters")
		case !secretNamePattern.MatchString(name):
			return errors.New("the name may only contain letters, digits and / _ + = . @ -")
		}
	default:
		return fmt.Errorf("unknown item kind %q", kind)
	}
	return nil
}

// MaxValueBytes returns the largest value AWS accepts for an item.
// For SSM it depends on the tier.
func MaxValueBytes(kind Kind, ssmTier string) int {
	switch {
	case kind == KindSecret:
		return 65536
	case ssmTier == SSMTierAdvanced:
		return 8192
	default:
		return 4096
	}
}

// Tag is a key=value tag on an item.
type Tag struct {
	Key   string
	Value string
}

// HasAnyTag reports whether tags contain one of wanted. Keys must match
// exactly; values match without regard to case ("true" and "True").
func HasAnyTag(tags map[string]string, wanted []Tag) bool {
	for _, w := range wanted {
		if value, ok := tags[w.Key]; ok && strings.EqualFold(value, w.Value) {
			return true
		}
	}
	return false
}

// SSM parameter types and tiers.
const (
	SSMTypeString       = "String"
	SSMTypeStringList   = "StringList"
	SSMTypeSecureString = "SecureString"

	SSMTierStandard = "Standard"
	SSMTierAdvanced = "Advanced"
)

// SSMTypes lists the parameter types users can choose.
var SSMTypes = []string{SSMTypeSecureString, SSMTypeString, SSMTypeStringList}

// SSMTiers lists the parameter tiers users can choose.
var SSMTiers = []string{SSMTierStandard, SSMTierAdvanced}
