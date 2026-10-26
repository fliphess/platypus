-- Teams can link to one identity-provider group, and users remember the
-- groups their login reported. Both columns are additive: web pods of the
-- previous release keep working during a rollout.

ALTER TABLE teams ADD COLUMN idp_group text;

-- A group feeds at most one team, so a link is unambiguous.
CREATE UNIQUE INDEX teams_idp_group_key ON teams (idp_group) WHERE idp_group IS NOT NULL;

ALTER TABLE users ADD COLUMN idp_groups text[] NOT NULL DEFAULT '{}';
