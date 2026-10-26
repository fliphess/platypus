-- name: GetNote :one
SELECT * FROM notes WHERE kind = @kind AND name = @name;

-- name: ListNotesForKind :many
SELECT * FROM notes WHERE kind = @kind ORDER BY name;

-- name: SaveNote :exec
INSERT INTO notes (kind, name, body, updated_by)
VALUES (@kind, @name, @body, @updated_by)
ON CONFLICT (kind, name) DO UPDATE
SET body = excluded.body, updated_by = excluded.updated_by, updated_at = now();

-- name: DeleteNote :exec
DELETE FROM notes WHERE kind = @kind AND name = @name;

-- Notes whose item no longer exists in AWS (or is hidden).
-- name: CountOrphanedNotes :one
SELECT count(*) FROM notes n
LEFT JOIN items i ON n.kind = i.kind AND n.name = i.name AND i.access = 'ok'
WHERE i.name is null;

-- name: ListOrphanedNotesPage :many
SELECT n.* FROM notes n
LEFT JOIN items i ON n.kind = i.kind AND n.name = i.name AND i.access = 'ok'
WHERE i.name is null
ORDER BY n.kind, n.name
LIMIT @max_rows OFFSET @row_offset;
