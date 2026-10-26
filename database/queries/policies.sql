-- name: ListPolicies :many
SELECT p.*,
       (SELECT count(*) FROM policy_rules r WHERE r.policy_id = p.id) AS rule_count,
       (SELECT count(*) FROM user_policies up WHERE up.policy_id = p.id) AS user_count,
       (SELECT count(*) FROM team_policies tp WHERE tp.policy_id = p.id) AS team_count
FROM policies p
WHERE (@search::text = '' OR p.name ILIKE @search OR p.description ILIKE @search)
ORDER BY p.name;

-- name: GetPolicy :one
SELECT * FROM policies WHERE id = @id;

-- name: CreatePolicy :one
INSERT INTO policies (name, description) VALUES (@name, @description) RETURNING *;

-- name: UpdatePolicy :exec
UPDATE policies SET name = @name, description = @description, updated_at = now() WHERE id = @id;

-- name: DeletePolicy :exec
DELETE FROM policies WHERE id = @id;

-- name: ListPolicyRules :many
SELECT * FROM policy_rules WHERE policy_id = @policy_id ORDER BY position, id;

-- name: DeletePolicyRules :exec
DELETE FROM policy_rules WHERE policy_id = @policy_id;

-- name: InsertPolicyRule :exec
INSERT INTO policy_rules (policy_id, kind, pattern, can_list, can_create, can_edit, can_reveal, position)
VALUES (@policy_id, @kind, @pattern, @can_list, @can_create, @can_edit, @can_reveal, @position);

-- name: ListUserPolicies :many
SELECT p.* FROM policies p
INNER JOIN user_policies up ON p.id = up.policy_id
WHERE up.user_id = @user_id
ORDER BY p.name;

-- name: AssignPolicyToUser :exec
INSERT INTO user_policies (user_id, policy_id) VALUES (@user_id, @policy_id) ON CONFLICT DO NOTHING;

-- name: UnassignPolicyFromUser :exec
DELETE FROM user_policies WHERE user_id = @user_id AND policy_id = @policy_id;

-- name: ListTeamPolicies :many
SELECT p.* FROM policies p
INNER JOIN team_policies tp ON p.id = tp.policy_id
WHERE tp.team_id = @team_id
ORDER BY p.name;

-- name: AssignPolicyToTeam :exec
INSERT INTO team_policies (team_id, policy_id) VALUES (@team_id, @policy_id) ON CONFLICT DO NOTHING;

-- name: UnassignPolicyFromTeam :exec
DELETE FROM team_policies WHERE team_id = @team_id AND policy_id = @policy_id;

-- name: ListPolicyUsers :many
SELECT u.* FROM users u
INNER JOIN user_policies up ON u.id = up.user_id
WHERE up.policy_id = @policy_id
ORDER BY u.email;

-- name: ListPolicyTeams :many
SELECT t.* FROM teams t
INNER JOIN team_policies tp ON t.id = tp.team_id
WHERE tp.policy_id = @policy_id
ORDER BY t.name;

-- Every rule that applies to a user: through policies assigned to the user
-- directly (team_name is empty) and through the user's teams.
-- name: ListRulesForUser :many
SELECT r.kind, r.pattern, r.can_list, r.can_create, r.can_edit, r.can_reveal,
       p.name AS policy_name, ''::text AS team_name
FROM user_policies up
INNER JOIN policies p ON up.policy_id = p.id
INNER JOIN policy_rules r ON p.id = r.policy_id
WHERE up.user_id = @user_id
UNION ALL
SELECT r.kind, r.pattern, r.can_list, r.can_create, r.can_edit, r.can_reveal,
       p.name AS policy_name, t.name AS team_name
FROM team_members m
INNER JOIN teams t ON m.team_id = t.id
INNER JOIN team_policies tp ON t.id = tp.team_id
INNER JOIN policies p ON tp.policy_id = p.id
INNER JOIN policy_rules r ON p.id = r.policy_id
WHERE m.user_id = @user_id
ORDER BY policy_name, team_name, kind, pattern;
