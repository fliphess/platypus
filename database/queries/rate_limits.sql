-- Counts one hit in a fixed window and returns the count so far.
-- name: HitRateLimit :one
INSERT INTO rate_limit_counters (key, window_start, count)
VALUES (@key, @window_start, 1)
ON CONFLICT (key, window_start) DO UPDATE SET count = rate_limit_counters.count + 1
RETURNING count;

-- name: DeleteRateLimitsBefore :exec
DELETE FROM rate_limit_counters WHERE window_start < @before;
