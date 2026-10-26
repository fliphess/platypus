// Package access manages who may do what: users, teams, policies and the
// rules they grant. It turns them into an authz.Subject for permission checks.
package access

import (
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"platypus/internal/audit"
	"platypus/internal/db"
	"platypus/internal/problem"
)

// Service manages users, teams and policies. Changes are audited.
type Service struct {
	pool           *pgxpool.Pool
	queries        *db.Queries
	audit          *audit.Recorder
	allowedDomains []string
	now            func() time.Time
}

// NewService returns a Service. allowedDomains are the email domains that may
// use platypus.
func NewService(pool *pgxpool.Pool, recorder *audit.Recorder, allowedDomains []string) *Service {
	return &Service{
		pool:           pool,
		queries:        db.New(pool),
		audit:          recorder,
		allowedDomains: allowedDomains,
		now:            time.Now,
	}
}

// ParseEmail normalises an email address and checks that its domain may use
// platypus. Display names ("Jane <jane@example.com>") are not accepted.
func ParseEmail(raw string, allowedDomains []string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" {
		return "", problem.Invalid("An email address is required.")
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || parsed.Name != "" {
		return "", problem.Invalid("%q is not a valid email address.", raw)
	}
	_, domain, _ := strings.Cut(email, "@")
	if !slices.Contains(allowedDomains, domain) {
		return "", problem.Invalid("Email addresses from %s can't use platypus.", domain)
	}
	return email, nil
}
