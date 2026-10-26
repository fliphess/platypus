-- name: InsertAuditEvent :exec
INSERT INTO audit_events (actor_id, actor_email, action, outcome, resource_kind, resource_name,
                          reason, client_ip, user_agent, request_id, details)
VALUES (sqlc.narg(actor_id), @actor_email, @action, @outcome, @resource_kind, @resource_name,
        @reason, @client_ip, @user_agent, @request_id, @details);

-- Newest first, paginated by id: pass the last id seen as before_id.
-- name: ListAuditEvents :many
SELECT * FROM audit_events
WHERE (sqlc.narg(before_id)::bigint is null OR id < sqlc.narg(before_id)::bigint)
  AND (sqlc.narg(since)::timestamptz is null OR occurred_at >= sqlc.narg(since)::timestamptz)
  AND (sqlc.narg(until)::timestamptz is null OR occurred_at < sqlc.narg(until)::timestamptz)
  AND (sqlc.narg(actor_email)::text is null OR actor_email = sqlc.narg(actor_email)::text)
  AND (sqlc.narg(action)::text is null OR action = sqlc.narg(action)::text)
  AND (sqlc.narg(outcome)::text is null OR outcome = sqlc.narg(outcome)::text)
  AND (sqlc.narg(search)::text is null
       OR actor_email ILIKE sqlc.narg(search)::text
       OR action ILIKE sqlc.narg(search)::text
       OR outcome ILIKE sqlc.narg(search)::text
       OR resource_name ILIKE sqlc.narg(search)::text
       OR reason ILIKE sqlc.narg(search)::text
       OR details::text ILIKE sqlc.narg(search)::text)
ORDER BY id DESC
LIMIT @max_rows;

-- CountAuditEvents counts the events a filter matches, so the trail can show
-- real pages instead of a chain of "older" links.
-- name: CountAuditEvents :one
SELECT count(*) FROM audit_events
WHERE (sqlc.narg(since)::timestamptz is null OR occurred_at >= sqlc.narg(since)::timestamptz)
  AND (sqlc.narg(until)::timestamptz is null OR occurred_at < sqlc.narg(until)::timestamptz)
  AND (sqlc.narg(actor_email)::text is null OR actor_email = sqlc.narg(actor_email)::text)
  AND (sqlc.narg(action)::text is null OR action = sqlc.narg(action)::text)
  AND (sqlc.narg(outcome)::text is null OR outcome = sqlc.narg(outcome)::text)
  AND (sqlc.narg(search)::text is null
       OR actor_email ILIKE sqlc.narg(search)::text
       OR action ILIKE sqlc.narg(search)::text
       OR outcome ILIKE sqlc.narg(search)::text
       OR resource_name ILIKE sqlc.narg(search)::text
       OR reason ILIKE sqlc.narg(search)::text
       OR details::text ILIKE sqlc.narg(search)::text);

-- name: ListAuditEventsPage :many
SELECT * FROM audit_events
WHERE (sqlc.narg(since)::timestamptz is null OR occurred_at >= sqlc.narg(since)::timestamptz)
  AND (sqlc.narg(until)::timestamptz is null OR occurred_at < sqlc.narg(until)::timestamptz)
  AND (sqlc.narg(actor_email)::text is null OR actor_email = sqlc.narg(actor_email)::text)
  AND (sqlc.narg(action)::text is null OR action = sqlc.narg(action)::text)
  AND (sqlc.narg(outcome)::text is null OR outcome = sqlc.narg(outcome)::text)
  AND (sqlc.narg(search)::text is null
       OR actor_email ILIKE sqlc.narg(search)::text
       OR action ILIKE sqlc.narg(search)::text
       OR outcome ILIKE sqlc.narg(search)::text
       OR resource_name ILIKE sqlc.narg(search)::text
       OR reason ILIKE sqlc.narg(search)::text
       OR details::text ILIKE sqlc.narg(search)::text)
ORDER BY id DESC
LIMIT @max_rows OFFSET @row_offset;

-- Deletes one batch of events older than a moment; call until it returns 0.
-- name: PruneAuditEvents :execrows
DELETE FROM audit_events AS a
WHERE a.id IN (
    SELECT e.id FROM audit_events AS e
    WHERE e.occurred_at < @before
    ORDER BY e.id
    LIMIT @batch_size
);
