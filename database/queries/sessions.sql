-- name: CreateSession :exec
INSERT INTO sessions (id_hash, user_id, csrf_token, expires_at)
VALUES (@id_hash, @user_id, @csrf_token, @expires_at);

-- name: GetSession :one
SELECT * FROM sessions WHERE id_hash = @id_hash AND expires_at > now();

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = now(), expires_at = @expires_at WHERE id_hash = @id_hash;

-- name: SetAdminMode :exec
UPDATE sessions SET admin_mode_until = sqlc.narg(admin_mode_until) WHERE id_hash = @id_hash;

-- name: SetSessionBootstrapToken :exec
UPDATE sessions SET bootstrap_token_id = sqlc.narg(bootstrap_token_id) WHERE id_hash = @id_hash;

-- name: SaveWebAuthnCeremony :exec
INSERT INTO webauthn_ceremonies (id_hash, ceremony, ceremony_until)
VALUES (@id_hash, @ceremony, @ceremony_until)
ON CONFLICT (id_hash) DO UPDATE
SET ceremony = excluded.ceremony, ceremony_until = excluded.ceremony_until;

-- A finish takes the ceremony by deleting it: only one request can win, even
-- if two arrive concurrently.
-- name: TakeWebAuthnCeremony :one
DELETE FROM webauthn_ceremonies
WHERE id_hash = @id_hash AND ceremony_until > now()
RETURNING ceremony;

-- name: ClearWebAuthnCeremony :exec
DELETE FROM webauthn_ceremonies WHERE id_hash = @id_hash;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id_hash = @id_hash;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = @user_id;

-- name: EndAllAdminModes :exec
UPDATE sessions SET admin_mode_until = null WHERE admin_mode_until is not null;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at <= now();
