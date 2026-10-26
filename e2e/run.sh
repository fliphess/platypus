#!/usr/bin/env bash
# Runs the browser tests in Docker against a fresh docker-compose stack.
# Needs nothing but Docker; screenshots end up in e2e/shots/.
#
# The tests run in their own compose project (platypus-e2e), separate from a
# dev stack on the default project: a test run never touches dev data, and
# its cleanup never wipes the dev database.
set -euo pipefail

cd "$(dirname "$0")/.."
playwright_image="mcr.microsoft.com/playwright:v1.56.0-noble"
compose="docker compose -p platypus-e2e -f docker-compose.yaml -f e2e/compose.e2e.yaml"

cleanup() { $compose --profile oidc down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Chrome accepts admin.localhost as a passkey domain, so the passkey steps run.
export PLATYPUS_PASSKEYS_ENABLED=true
# The oidc-mode platypus, as the browser in the test container reaches it
# (see browser.test.mjs for why it gets a *.localhost name).
export PLATYPUS_OIDC_PUBLIC_URL=http://oidc.localhost:8080

$compose --profile oidc down -v >/dev/null 2>&1 || true
$compose --profile oidc up -d --build --wait web worker dev-proxy dex web-oidc

read_token() {
  docker run --rm --network platypus-e2e_default \
    -e AWS_ACCESS_KEY_ID=test -e AWS_SECRET_ACCESS_KEY=test -e AWS_REGION=eu-west-1 \
    amazon/aws-cli:2.38.5 --endpoint-url http://ministack:4566 ssm get-parameter --with-decryption \
    --name /platypus/bootstrap-token --query Parameter.Value --output text 2>/dev/null || true
}

token=""
for _ in $(seq 1 30); do
  token=$(read_token)
  [ -n "$token" ] && break
  sleep 1
done
[ -n "$token" ] || { echo "the worker issued no bootstrap token" >&2; exit 1; }

mkdir -p e2e/shots docs/images
docker run --rm --network platypus-e2e_default -e BOOTSTRAP_TOKEN="$token" \
  -e DOCS_SHOTS="${DOCS_SHOTS:-}" \
  -v "$PWD/e2e:/work" -v "$PWD/docs/images:/work/docs-images" -w /work "$playwright_image" \
  bash -c "npm install --silent --no-audit --no-fund && node browser.test.mjs"
