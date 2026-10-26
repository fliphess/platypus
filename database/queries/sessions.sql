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

-- name: SetWebAuthnCeremony :exec
UPDATE sessions
SET webauthn_ceremony = @ceremony, webauthn_ceremony_until = @ceremony_until
WHERE id_hash = @id_hash;

-- name: TakeWebAuthnCeremony :one
UPDATE sessions
SET webauthn_ceremony = null, webauthn_ceremony_until = null
WHERE id_hash = @id_hash AND webauthn_ceremony is not null
  AND webauthn_ceremony_until is not null AND webauthn_ceremony_until > now()
RETURNING webauthn_ceremony;

-- name: ClearWebAuthnCeremony :exec
UPDATE sessions SET webauthn_ceremony = null, webauthn_ceremony_until = null WHERE id_hash = @id_hash;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id_hash = @id_hash;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = @user_id;

-- name: EndAllAdminModes :exec
UPDATE sessions SET admin_mode_until = null WHERE admin_mode_until is not null;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at <= now();
