-- name: GetAppState :one
SELECT * FROM app_state;

-- name: SetBootstrapped :exec
UPDATE app_state SET bootstrapped = @bootstrapped;

-- Claims the one-time seeding of default policies. Returns no row when they
-- were seeded before.
-- name: ClaimPolicySeeding :one
UPDATE app_state SET policies_seeded = true
WHERE NOT policies_seeded
RETURNING policies_seeded;

-- name: SetBlocked :exec
UPDATE app_state SET blocked_at = now(), blocked_by = @blocked_by;

-- name: ClearBlocked :exec
UPDATE app_state SET blocked_at = null, blocked_by = null;

-- name: RequestSync :exec
UPDATE app_state
SET sync_requested_at = now(),
    sync_requested_by = @requested_by,
    sync_recheck_access = sync_recheck_access OR @recheck_access;

-- Takes a pending sync request, if any, and clears it.
-- name: TakeSyncRequest :one
WITH pending AS (
    SELECT sync_requested_by, sync_recheck_access
    FROM app_state
    WHERE sync_requested_at is not null
    FOR UPDATE
)

UPDATE app_state
SET sync_requested_at = null, sync_requested_by = null, sync_recheck_access = false
FROM pending
RETURNING pending.sync_requested_by, pending.sync_recheck_access;
