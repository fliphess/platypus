package config

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"platypus/internal/item"
	"platypus/internal/sensitive"
)

// reader reads typed values from the environment and collects every problem,
// so a misconfigured deployment reports all mistakes at once.
type reader struct {
	getenv func(string) string
	errs   []error
}

// raw returns the value of v, its default when unset, and records an error
// when a required variable is missing.
func (r *reader) raw(v Var) string {
	value := strings.TrimSpace(r.getenv(v.Name))
	if value == "" {
		value = v.Default
	}
	if value == "" && v.Required {
		r.fail(v, "is required")
	}
	return value
}

func (r *reader) fail(v Var, format string, args ...any) {
	r.errs = append(r.errs, fmt.Errorf("%s %s", v.Name, fmt.Sprintf(format, args...)))
}

func (r *reader) string(v Var) string {
	return r.raw(v)
}

// rawExact is raw without normalisation: a secret is opaque, so significant
// leading or trailing whitespace must survive.
func (r *reader) rawExact(v Var) string {
	value := r.getenv(v.Name)
	if value == "" {
		value = v.Default
	}
	if value == "" && v.Required {
		r.fail(v, "is required")
	}
	return value
}

func (r *reader) secret(v Var) sensitive.Value {
	return sensitive.New(r.rawExact(v))
}

func (r *reader) oneOf(v Var, allowed ...string) string {
	value := r.raw(v)
	if value != "" && !slices.Contains(allowed, value) {
		r.fail(v, "must be one of %s, got %q", strings.Join(allowed, ", "), value)
	}
	return value
}

func (r *reader) bool(v Var) bool {
	value := r.raw(v)
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		r.fail(v, "must be true or false, got %q", value)
	}
	return parsed
}

func (r *reader) int(v Var) int {
	value := r.raw(v)
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		r.fail(v, "must be a whole number, got %q", value)
	}
	return parsed
}

func (r *reader) duration(v Var) time.Duration {
	value := r.raw(v)
	if value == "" {
		return 0
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		r.fail(v, "must be a duration like 30s, 15m or 24h, got %q", value)
	}
	return parsed
}

// url parses an absolute http(s) URL without path, query or fragment.
func (r *reader) url(v Var) *url.URL {
	value := r.raw(v)
	parsed, err := url.Parse(value)
	if value == "" || err != nil || parsed.Host == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") ||
		strings.Trim(parsed.Path, "/") != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		if value != "" {
			r.fail(v, "must be a URL like https://platypus.example.com, got %q", value)
		}
		return &url.URL{}
	}
	parsed.Path = ""
	return parsed
}

// tags reads comma-separated key=value pairs.
func (r *reader) tags(v Var) []item.Tag {
	var tags []item.Tag
	for pair := range strings.SplitSeq(r.raw(v), ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		key, value, ok := strings.Cut(pair, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || key == "" || value == "" {
			r.fail(v, "must be key=value pairs, got %q", pair)
			continue
		}
		tags = append(tags, item.Tag{Key: key, Value: value})
	}
	return tags
}

// rawList splits a comma-separated value and drops empty items, keeping case.
func (r *reader) rawList(v Var) []string {
	var entries []string
	for entry := range strings.SplitSeq(r.raw(v), ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}

// list splits a comma-separated value, lowercases the items and drops empty ones.
func (r *reader) list(v Var) []string {
	var entries []string
	for entry := range strings.SplitSeq(r.raw(v), ",") {
		if entry = strings.ToLower(strings.TrimSpace(entry)); entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}
