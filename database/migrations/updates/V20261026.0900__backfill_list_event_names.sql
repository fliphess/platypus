-- List events used to be stored without a resource name, so the audit view
-- showed "none" for them. The name is derivable from the event's own details
-- (the resource kind and the search term), so backfill it. New events are
-- named when they are recorded.
UPDATE audit_events
SET resource_name = CASE resource_kind
        WHEN 'secret' THEN '/secrets'
        ELSE '/ssm'
    END
    || CASE
        WHEN coalesce(details ->> 'search', '') <> '' THEN '?q=' || (details ->> 'search')
        ELSE ''
    END
WHERE action = 'item.list'
  AND resource_name = '';
