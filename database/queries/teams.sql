-- name: ListTeams :many
SELECT t.*, (SELECT count(*) FROM team_members m WHERE m.team_id = t.id) AS member_count,
       (SELECT count(*) FROM team_policies tp WHERE tp.team_id = t.id) AS policy_count
FROM teams t
WHERE (@search::text = '' OR t.name ILIKE @search OR t.description ILIKE @search)
ORDER BY t.name;

-- name: CountTeams :one
SELECT count(*) FROM teams t
WHERE (@search::text = '' OR t.name ILIKE @search OR t.description ILIKE @search);

-- name: ListTeamsPage :many
SELECT t.*, (SELECT count(*) FROM team_members m WHERE m.team_id = t.id) AS member_count,
       (SELECT count(*) FROM team_policies tp WHERE tp.team_id = t.id) AS policy_count
FROM teams t
WHERE (@search::text = '' OR t.name ILIKE @search OR t.description ILIKE @search)
ORDER BY t.name
LIMIT @max_rows OFFSET @row_offset;

-- name: GetTeam :one
SELECT * FROM teams WHERE id = @id;

-- name: CreateTeam :one
INSERT INTO teams (name, description, idp_group) VALUES (@name, @description, sqlc.narg(idp_group)) RETURNING *;

-- name: UpdateTeam :exec
UPDATE teams SET name = @name, description = @description, idp_group = sqlc.narg(idp_group) WHERE id = @id;

-- name: DeleteTeam :exec
DELETE FROM teams WHERE id = @id;

-- name: ListTeamMembers :many
SELECT u.* FROM users u
INNER JOIN team_members m ON u.id = m.user_id
WHERE m.team_id = @team_id
ORDER BY u.email;

-- name: AddTeamMember :exec
INSERT INTO team_members (team_id, user_id) VALUES (@team_id, @user_id) ON CONFLICT DO NOTHING;

-- name: RemoveTeamMember :exec
DELETE FROM team_members WHERE team_id = @team_id AND user_id = @user_id;

-- Group-linked teams: membership follows the user's groups. Adds the user to
-- every linked team whose group is one of theirs; returns the teams that
-- changed (a team id, once per team).
-- name: AddUserToGroupTeams :many
INSERT INTO team_members (team_id, user_id)
SELECT t.id, @user_id FROM teams t
WHERE t.idp_group = any(@groups::text[])
ON CONFLICT DO NOTHING
RETURNING team_id;

-- Removes the user from linked teams whose group is no longer theirs;
-- returns the teams that changed.
-- name: RemoveUserFromOtherGroupTeams :many
DELETE FROM team_members m
USING teams t
WHERE m.team_id = t.id
  AND m.user_id = @user_id
  AND t.idp_group is not null
  AND t.idp_group <> all(@groups::text[])
RETURNING m.team_id;

-- name: ListUserTeams :many
SELECT t.* FROM teams t
INNER JOIN team_members m ON t.id = m.team_id
WHERE m.user_id = @user_id
ORDER BY t.name;
