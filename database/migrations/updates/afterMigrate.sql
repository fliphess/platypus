-- Flyway runs this after every migration. It (re)applies the grants for the
-- application roles on all objects in the platypus schema, so new tables are
-- covered without each migration repeating the grants.

-- platypus_rw: the role the application connects with.
GRANT USAGE ON SCHEMA platypus TO platypus_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA platypus TO platypus_rw;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA platypus TO platypus_rw;

-- The audit trail is append-only for the application: it may add events and
-- prune old ones, but never change an existing event.
REVOKE UPDATE ON platypus.audit_events FROM platypus_rw;

-- platypus_ro: read-only access, for example for debugging.
GRANT USAGE ON SCHEMA platypus TO platypus_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA platypus TO platypus_ro;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA platypus TO platypus_ro;
