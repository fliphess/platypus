-- name: CreateBootstrapToken :one
INSERT INTO bootstrap_tokens (token_hash, issued_by, expires_at)
VALUES (@token_hash, @issued_by, @expires_at)
RETURNING id;

-- name: RevokeBootstrapTokens :exec
UPDATE bootstrap_tokens SET revoked_at = now() WHERE used_at is null AND revoked_at is null;

-- name: ListValidBootstrapTokens :many
SELECT id, token_hash FROM bootstrap_tokens
WHERE used_at is null AND revoked_at is null AND expires_at > now()
ORDER BY id DESC;

-- name: IsBootstrapTokenValid :one
SELECT exists(
    SELECT 1 FROM bootstrap_tokens
    WHERE id = @id AND used_at is null AND revoked_at is null AND expires_at > now()
);

-- Uses a token, once. Returns no row when it is used, revoked or expired.
-- name: UseBootstrapToken :one
UPDATE bootstrap_tokens
SET used_at = now(), used_by = @used_by
WHERE id = @id AND used_at is null AND revoked_at is null AND expires_at > now()
RETURNING id;
