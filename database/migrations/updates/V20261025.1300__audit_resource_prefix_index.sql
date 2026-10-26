-- The audit trail filters on a resource name prefix (LIKE 'prefix%'). A plain
-- btree can't serve that outside the C locale; text_pattern_ops can.
DROP INDEX audit_events_resource_name_idx;
CREATE INDEX audit_events_resource_name_idx ON audit_events (resource_name text_pattern_ops, occurred_at);
