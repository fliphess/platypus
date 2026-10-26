-- Prepares a fresh container Postgres (docker-compose and CI) for platypus.
--
-- Runs once, from /docker-entrypoint-initdb.d, as the postgres superuser in
-- the database named by POSTGRES_DB. On RDS (acc and prd) the platform sets up
-- the same database, roles and schema; keep this file in line with that.
-- Flyway then creates the tables (database/migrations/updates).
--
-- The passwords below are for local use only.

ALTER DATABASE platypus SET timezone TO 'UTC';
REVOKE CONNECT ON DATABASE platypus FROM PUBLIC;

-- Owner of the database and the schema; Flyway runs as this user. Like on
-- RDS it can create tables and trusted extensions, but not roles or databases.
CREATE USER platypus_migrations PASSWORD 'platypus_migrations_local';
ALTER DATABASE platypus OWNER TO platypus_migrations;
CREATE SCHEMA platypus AUTHORIZATION platypus_migrations;

-- The application user.
CREATE USER platypus_rw PASSWORD 'platypus_rw_local';
GRANT CONNECT ON DATABASE platypus TO platypus_rw;

-- Read-only access, for example for debugging.
CREATE USER platypus_ro PASSWORD 'platypus_ro_local';
GRANT CONNECT ON DATABASE platypus TO platypus_ro;
