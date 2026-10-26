-- name: StartSyncRun :one
INSERT INTO sync_runs (trigger, recheck_access) VALUES (@trigger, @recheck_access) RETURNING id, started_at;

-- name: FinishSyncRun :exec
UPDATE sync_runs
SET finished_at = now(),
    status = @status,
    parameters_seen = @parameters_seen,
    secrets_seen = @secrets_seen,
    access_checked = @access_checked,
    message = @message
WHERE id = @id;

-- name: GetLatestSyncRun :one
SELECT * FROM sync_runs ORDER BY id DESC LIMIT 1;

-- name: GetLatestSuccessfulRecheck :one
SELECT started_at FROM sync_runs
WHERE status = 'succeeded' AND recheck_access
ORDER BY id DESC
LIMIT 1;

-- name: FailUnfinishedSyncRuns :exec
UPDATE sync_runs
SET finished_at = now(), status = 'failed', message = 'interrupted'
WHERE status = 'running';

-- name: DeleteSyncRunsBefore :exec
DELETE FROM sync_runs WHERE started_at < @before;
