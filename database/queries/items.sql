-- Inserts or refreshes a parameter from AWS. When it changed since the last
-- sync, its access check is reset. Without synced_at the database clock is
-- used, the clock the sync compares against.
-- name: UpsertParameter :exec
INSERT INTO items (kind, name, description, kms_key_id, last_modified_at, change_marker,
                   ssm_type, ssm_tier, ssm_data_type, ssm_version, access, synced_at)
VALUES ('ssm', @name, @description, @kms_key_id, @last_modified_at, @change_marker,
        @ssm_type, @ssm_tier, @ssm_data_type, @ssm_version, @access, coalesce(sqlc.narg(synced_at)::timestamptz, now()))
ON CONFLICT (kind, name) DO UPDATE
SET description = excluded.description,
    kms_key_id = excluded.kms_key_id,
    last_modified_at = excluded.last_modified_at,
    change_marker = excluded.change_marker,
    ssm_type = excluded.ssm_type,
    ssm_tier = excluded.ssm_tier,
    ssm_data_type = excluded.ssm_data_type,
    ssm_version = excluded.ssm_version,
    access = CASE
        WHEN excluded.access <> 'unknown' THEN excluded.access
        WHEN items.change_marker <> excluded.change_marker THEN 'unknown'
        ELSE items.access
    END,
    access_checked_at = CASE
        WHEN excluded.access <> 'unknown' THEN now()
        WHEN items.change_marker <> excluded.change_marker THEN null
        ELSE items.access_checked_at
    END,
    synced_at = excluded.synced_at;

-- Inserts or refreshes a secret from AWS; see UpsertParameter.
-- name: UpsertSecret :exec
INSERT INTO items (kind, name, description, kms_key_id, last_modified_at, change_marker,
                   secret_arn, secret_version_id, rotation_enabled, deleted_at, tags, access, synced_at)
VALUES ('secret', @name, @description, @kms_key_id, @last_modified_at, @change_marker,
        @secret_arn, @secret_version_id, @rotation_enabled, sqlc.narg(deleted_at), @tags, @access, coalesce(sqlc.narg(synced_at)::timestamptz, now()))
ON CONFLICT (kind, name) DO UPDATE
SET description = excluded.description,
    kms_key_id = excluded.kms_key_id,
    last_modified_at = excluded.last_modified_at,
    change_marker = excluded.change_marker,
    secret_arn = excluded.secret_arn,
    secret_version_id = excluded.secret_version_id,
    rotation_enabled = excluded.rotation_enabled,
    deleted_at = excluded.deleted_at,
    tags = excluded.tags,
    access = CASE
        WHEN excluded.access <> 'unknown' THEN excluded.access
        WHEN items.change_marker <> excluded.change_marker THEN 'unknown'
        ELSE items.access
    END,
    access_checked_at = CASE
        WHEN excluded.access <> 'unknown' THEN now()
        WHEN items.change_marker <> excluded.change_marker THEN null
        ELSE items.access_checked_at
    END,
    synced_at = excluded.synced_at;

-- Removes items a complete sync no longer saw in AWS.
-- name: DeleteItemsNotSyncedSince :execrows
DELETE FROM items WHERE kind = @kind AND synced_at < @since;

-- Items whose access has not been checked, or not since a moment.
-- name: ListItemsToCheck :many
SELECT name FROM items
WHERE kind = @kind
  AND (access = 'unknown' OR access_checked_at is null OR access_checked_at < @checked_before)
ORDER BY name;

-- name: SetItemAccess :exec
UPDATE items SET access = @access, access_checked_at = now() WHERE kind = @kind AND name = @name;

-- name: SetItemTags :exec
UPDATE items SET tags = @tags WHERE kind = @kind AND name = @name;

-- An item platypus can access. Hidden items are reported as not found.
-- name: GetItem :one
SELECT * FROM items WHERE kind = @kind AND name = @name AND access = 'ok';

-- Items a user may see, optionally filtered by a search term on name,
-- description and note, one page at a time. The LIKE patterns come from the
-- user's rules; the caller escapes them and the search term.
-- name: ListVisibleItems :many
SELECT i.kind, i.name, i.description, i.last_modified_at, i.ssm_type, i.ssm_tier, i.rotation_enabled, i.secret_arn, i.deleted_at, i.tags,
       (n.body is not null)::boolean AS has_note
FROM items i
LEFT JOIN notes n ON i.kind = n.kind AND i.name = n.name
WHERE i.kind = @kind
  AND i.access = 'ok'
  AND i.name LIKE any(@allowed::text[])
  AND (@search::text = ''
       OR i.name ILIKE @search::text
       OR i.description ILIKE @search::text
       OR n.body ILIKE @search::text)
ORDER BY i.name
LIMIT @max_rows OFFSET @skip;

-- Counts what ListVisibleItems pages through.
-- name: CountListedItems :one
SELECT count(*)
FROM items i
LEFT JOIN notes n ON i.kind = n.kind AND i.name = n.name
WHERE i.kind = @kind
  AND i.access = 'ok'
  AND i.name LIKE any(@allowed::text[])
  AND (@search::text = ''
       OR i.name ILIKE @search::text
       OR i.description ILIKE @search::text
       OR n.body ILIKE @search::text);

-- name: CountVisibleItems :one
SELECT count(*) FROM items
WHERE kind = @kind AND access = 'ok' AND name LIKE any(@allowed::text[]);
