#!/usr/bin/env bash
# Seeds the local docker-compose stack with a lot of data, to review how the
# pages feel at scale: users, notes and audit events.
#   scripts/dev-seed-large.sh [users]      (default 200)
# Run against a stack that's already up (docker compose up --build).
set -euo pipefail

users="${1:-200}"

docker compose exec -T postgres psql -U postgres -d platypus <<SQL
BEGIN;
-- Users with profiles, spread over departments.
INSERT INTO platypus.users (email, is_admin, webauthn_handle, first_login_at, last_seen_at, display_name, department)
SELECT
  'person' || lpad(n::text, 3, '0') || '@example.com',
  false,
  decode(md5(random()::text), 'hex'),
  now() - (random() * interval '30 days'),
  now() - (random() * interval '3 days'),
  (ARRAY ['Ada','Bram','Cleo','Dilan','Eva','Finn','Gaia','Hugo'])[1 + n % 8] || ' Person' || n,
  (ARRAY ['Payments','Platform','Search','Mobile','Data','Security'])[1 + n % 6]
FROM generate_series(1, ${users}) AS n
ON CONFLICT (email) DO NOTHING;

-- Audit events for a third of them, spread over the last 30 days.
INSERT INTO platypus.audit_events (occurred_at, actor_id, actor_email, action, resource_type, resource_name, outcome, reason, client_ip, user_agent, request_id)
SELECT
  now() - (random() * interval '30 days'),
  u.id,
  u.email,
  (ARRAY ['item.view','item.reveal','item.update','item.create','item.search'])[1 + (u.id + n) % 5],
  (ARRAY ['ssm_parameter','secret'])[1 + u.id % 2],
  '/team' || n % 9 || '/app' || n % 6 || '/key' || n,
  (ARRAY ['allowed','allowed','allowed','denied'])[1 + (u.id + n) % 4],
  NULL,
  '10.0.0.' || (u.id % 254),
  'seed', 'seed', 'seed'
FROM platypus.users u, generate_series(1, 8) AS n
WHERE u.email LIKE 'person%@example.com'
ON CONFLICT DO NOTHING;
COMMIT;

SELECT
  (SELECT count(*) FROM platypus.users WHERE email LIKE 'person%@example.com') AS seeded_users,
  (SELECT count(*) FROM platypus.audit_events WHERE request_id = 'seed') AS seeded_events;
SQL

echo
echo "Users page:   http://admin.localhost:8090/admin/users  (50 per page)"
echo "Audit trail:  http://admin.localhost:8090/admin/audit   (filter by a person's name)"
