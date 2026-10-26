// Package ratelimit limits how often a user may do something, across all
// web replicas, with fixed-window counters in Postgres.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"platypus/internal/db"
)

// MaxWindow is the longest window a limit may use. Cleanup removes counters
// older than this, so a longer window would be reset halfway.
const MaxWindow = time.Hour

// Limiter counts hits per key and window.
type Limiter struct {
	queries *db.Queries
	now     func() time.Time
}

// New returns a Limiter.
func New(queries *db.Queries) *Limiter {
	return &Limiter{queries: queries, now: time.Now}
}

// Allow counts a hit for key and reports whether it stays within limit for
// the current window.
func (l *Limiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if window > MaxWindow {
		return false, fmt.Errorf("rate limit window %s is longer than %s", window, MaxWindow)
	}
	count, err := l.queries.HitRateLimit(ctx, db.HitRateLimitParams{
		Key:         key,
		WindowStart: l.now().Truncate(window),
	})
	if err != nil {
		return false, fmt.Errorf("rate limit: %w", err)
	}
	return int(count) <= limit, nil
}

// Cleanup removes counters of windows that have certainly ended.
func (l *Limiter) Cleanup(ctx context.Context) error {
	return l.queries.DeleteRateLimitsBefore(ctx, l.now().Add(-MaxWindow))
}
