#!/usr/bin/env bash
# Starts the docker-compose stack from an empty database and checks that a
# fresh platypus comes up: migrations applied, worker issued a bootstrap
# token, web serves the bootstrap page, identity headers from clients are
# ignored. Used by `make smoke` and the CI smoke job.
set -euo pipefail

cd "$(dirname "$0")/.."
# Where the compose ports are published: localhost, or the docker service in CI.
base="http://${SMOKE_HOST:-localhost}:8090"

cleanup() { docker compose down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker compose down -v >/dev/null 2>&1 || true
docker compose up -d --build --wait web worker dev-proxy

fail() { echo "smoke test failed: $*" >&2; docker compose logs web worker >&2; exit 1; }

echo "waiting for platypus..."
for _ in $(seq 1 60); do
  status=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: admin.localhost:8090' "$base/bootstrap" || true)
  [ "$status" = "200" ] && break
  sleep 1
done
[ "$status" = "200" ] || fail "bootstrap page returned $status"

curl -s -H 'Host: admin.localhost:8090' "$base/bootstrap" | grep -q 'Bootstrap token' || fail "bootstrap page has no token form"

status=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: other.localhost:8090' -H 'X-Auth-Request-Email: admin@example.com' "$base/")
[ "$status" = "401" ] || fail "a client-supplied identity header was accepted ($status)"

for _ in $(seq 1 30); do
  docker compose logs worker | grep -q 'issued a bootstrap token' && break
  sleep 1
done
docker compose logs worker | grep -q 'issued a bootstrap token' || fail "the worker issued no bootstrap token"

echo "smoke test passed"
