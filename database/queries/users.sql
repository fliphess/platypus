-- name: GetUser :one
SELECT * FROM users WHERE id = @id;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = @email;

-- Creates a user, or returns no row when the email exists already (for
-- example when two first requests race).
-- name: CreateUser :one
INSERT INTO users (email, webauthn_handle, created_by)
VALUES (@email, @webauthn_handle, sqlc.narg(created_by))
ON CONFLICT (email) DO NOTHING
RETURNING *;

-- name: RecordUserSeen :exec
UPDATE users
SET first_login_at = coalesce(first_login_at, now()),
    last_seen_at = now()
WHERE id = @id;

-- Users whose email or name contains the search term (all when null). The
-- caller lowercases and escapes the term.
-- name: ListUsers :many
SELECT * FROM users
WHERE sqlc.narg(search)::text is null
   OR email LIKE '%' || sqlc.narg(search)::text || '%'
   OR lower(display_name) LIKE '%' || sqlc.narg(search)::text || '%'
ORDER BY email
LIMIT @max_rows;

-- Users for the admin list, with how many policies reach them (directly or
-- through teams). Filters: a search term as in ListUsers, and only users
-- without any policy. The caller lowercases and escapes the term. Paged:
-- limit and offset come from the caller.
-- name: ListUsersWithAccess :many
SELECT sqlc.embed(u), counts.policies -- noqa: RF02
FROM users u
CROSS JOIN LATERAL (
    SELECT count(*) AS policies FROM (
        SELECT up.policy_id FROM user_policies up WHERE up.user_id = u.id
        UNION
        SELECT tp.policy_id FROM team_members tm INNER JOIN team_policies tp ON tm.team_id = tp.team_id
        WHERE tm.user_id = u.id
    ) reaching
) counts
WHERE (sqlc.narg(search)::text is null
       OR u.email LIKE '%' || sqlc.narg(search)::text || '%'
       OR lower(u.display_name) LIKE '%' || sqlc.narg(search)::text || '%')
  AND (NOT @without_access::boolean OR counts.policies = 0)
ORDER BY u.email
LIMIT @max_rows::int OFFSET @skip::int;

-- How many users match the admin list's filter, for the pager.
-- name: CountUsersWithAccess :one
SELECT count(*) FROM users u
CROSS JOIN LATERAL (
    SELECT count(*) AS policies FROM (
        SELECT up.policy_id FROM user_policies up WHERE up.user_id = u.id
        UNION
        SELECT tp.policy_id FROM team_members tm INNER JOIN team_policies tp ON tm.team_id = tp.team_id
        WHERE tm.user_id = u.id
    ) reaching
) counts
WHERE (sqlc.narg(search)::text is null
       OR u.email LIKE '%' || sqlc.narg(search)::text || '%'
       OR lower(u.display_name) LIKE '%' || sqlc.narg(search)::text || '%')
  AND (NOT @without_access::boolean OR counts.policies = 0);

-- People who logged in, aren't disabled and have no policy at all.
-- name: CountUsersWithoutAccess :one
SELECT count(*) FROM users u
WHERE u.first_login_at is not null
  AND u.disabled_at is null
  AND NOT exists (SELECT 1 FROM user_policies up WHERE up.user_id = u.id)
  AND NOT exists (SELECT 1 FROM team_members tm INNER JOIN team_policies tp ON tm.team_id = tp.team_id
                  WHERE tm.user_id = u.id);

-- Fills in the name from the identity provider, unless the user chose one.
-- name: FillDisplayName :exec
UPDATE users SET display_name = @display_name WHERE id = @id AND display_name = '';

-- name: UpdateProfile :exec
UPDATE users SET display_name = @display_name, department = @department, timezone = @timezone WHERE id = @id;

-- Remembers the groups the user's login reported, so they can be shown and
-- compared. Only writes when they changed: 0 rows means unchanged.
-- name: SetUserGroups :execrows
UPDATE users SET idp_groups = @groups WHERE id = @id AND idp_groups <> @groups;

-- name: SetUserAdmin :exec
UPDATE users SET is_admin = @is_admin WHERE id = @id;

-- name: SetUserDisabled :exec
UPDATE users SET disabled_at = CASE WHEN @disabled::boolean THEN now() END WHERE id = @id;

-- Admins who can still act: not disabled and not locked.
-- name: CountActiveAdmins :one
SELECT count(*) FROM users WHERE is_admin AND disabled_at is null AND locked_at is null;

-- Counts a failed second-factor attempt and locks the user once the limit is
-- reached.
-- name: RecordFailedAttempt :one
UPDATE users
SET failed_mfa_attempts = failed_mfa_attempts + 1,
    locked_at = CASE
        WHEN failed_mfa_attempts + 1 >= @max_attempts::integer THEN coalesce(locked_at, now())
        ELSE locked_at
    END
WHERE id = @id
RETURNING failed_mfa_attempts, locked_at;

-- name: ResetFailedAttempts :exec
UPDATE users SET failed_mfa_attempts = 0 WHERE id = @id AND failed_mfa_attempts > 0;

-- name: UnlockUser :exec
UPDATE users SET locked_at = null, failed_mfa_attempts = 0 WHERE id = @id;

-- Serialises changes to admins, so two admins can't remove each other at the
-- same moment and leave platypus without any. Call inside a transaction.
-- name: LockUser :one
SELECT id FROM users WHERE id = @id FOR UPDATE;

-- name: LockAdminChanges :exec
SELECT pg_advisory_xact_lock(7461001);

-- Policy names that reach each of these users (directly or through a team),
-- for the admin user list's expanded rows.
-- name: ListPolicyNamesForUsers :many
SELECT up.user_id, p.name AS policy_name
FROM user_policies up
INNER JOIN policies p ON up.policy_id = p.id
WHERE up.user_id = any(@user_ids::bigint[])
UNION
SELECT tm.user_id, p.name AS policy_name
FROM team_members tm
INNER JOIN team_policies tp ON tm.team_id = tp.team_id
INNER JOIN policies p ON tp.policy_id = p.id
WHERE tm.user_id = any(@user_ids::bigint[])
ORDER BY user_id, policy_name;
