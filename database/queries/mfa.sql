-- name: GetTOTP :one
SELECT * FROM totp_credentials WHERE user_id = @user_id;

-- Stores a new, unconfirmed TOTP secret. A confirmed secret is never
-- overwritten here; it has to be removed first.
-- name: SavePendingTOTP :exec
INSERT INTO totp_credentials (user_id, secret_ciphertext, key_id)
VALUES (@user_id, @secret_ciphertext, @key_id)
ON CONFLICT (user_id) DO UPDATE
SET secret_ciphertext = excluded.secret_ciphertext,
    key_id = excluded.key_id,
    last_used_step = 0,
    created_at = now()
WHERE totp_credentials.confirmed_at is null;

-- Accepts a TOTP time step, once. Returns no row when the step (or a later
-- one) was used before, which blocks replaying a code.
-- name: UseTOTPStep :one
UPDATE totp_credentials
SET last_used_step = @step,
    confirmed_at = coalesce(confirmed_at, now())
WHERE user_id = @user_id AND last_used_step < @step
RETURNING user_id;

-- name: DeleteTOTP :exec
DELETE FROM totp_credentials WHERE user_id = @user_id;

-- name: ListPasskeys :many
SELECT * FROM passkeys WHERE user_id = @user_id ORDER BY created_at;

-- name: CreatePasskey :exec
INSERT INTO passkeys (user_id, credential_id, credential, name)
VALUES (@user_id, @credential_id, @credential, @name);

-- name: UpdatePasskeyAfterLogin :exec
UPDATE passkeys SET credential = @credential, last_used_at = now() WHERE id = @id;

-- name: DeletePasskey :exec
DELETE FROM passkeys WHERE id = @id AND user_id = @user_id;

-- name: ListUnusedRecoveryCodes :many
SELECT id, code_hash FROM recovery_codes WHERE user_id = @user_id AND used_at is null;

-- Marks a recovery code used, once. Returns no row when it was used already.
-- name: UseRecoveryCode :one
UPDATE recovery_codes SET used_at = now() WHERE id = @id AND used_at is null RETURNING id;

-- name: DeleteRecoveryCodes :exec
DELETE FROM recovery_codes WHERE user_id = @user_id;

-- name: InsertRecoveryCode :exec
INSERT INTO recovery_codes (user_id, code_hash) VALUES (@user_id, @code_hash);

-- Removes all second factors of a user, for example after a bootstrap reset.
-- name: DeleteAllPasskeys :exec
DELETE FROM passkeys WHERE user_id = @user_id;
