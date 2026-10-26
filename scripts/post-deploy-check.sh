#!/usr/bin/env bash
# Checks a deployed platypus from outside, the way an attacker on the network
# would try it. Run it after every deploy, as a step in your deploy pipeline:
#
#   scripts/post-deploy-check.sh https://platypus.example.com header
#
# The second argument is PLATYPUS_AUTH_MODE: header, signed-header or oidc.
# It fails when a request without login gets in, or when a forged identity
# header is accepted.
set -euo pipefail

base="${1:?usage: post-deploy-check.sh <platypus URL> <header|signed-header|oidc>}"
mode="${2:?usage: post-deploy-check.sh <platypus URL> <header|signed-header|oidc>}"
host="$(echo "$base" | sed -E 's#https?://##; s#/.*##')"
forged="someone@${host}"

fail() { echo "post-deploy check failed: $*" >&2; exit 1; }

status_and_location() {
  curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' --max-time 15 "$@" || true
}

# 1. Without a login nobody gets in. With a login proxy (header and
#    signed-header mode) the proxy sends us to the identity provider; in oidc
#    mode platypus sends us to its own login, which goes to the provider.
read -r status location < <(status_and_location "$base/ssm")
case "$mode:$status" in
  oidc:303)
    [[ "$location" == "$base/auth/login"* ]] || fail "expected a redirect to $base/auth/login, got $location"
    read -r status location < <(status_and_location "$base/auth/login")
    [[ "$status" == "302" && "$location" != "$base"* ]] || fail "the login doesn't go to the identity provider ($status $location)"
    ;;
  header:30[237] | signed-header:30[237])
    [[ "$location" != "$base"* ]] || fail "unauthenticated request redirected inside platypus ($location)"
    ;;
  *:401 | *:403) ;;
  *) fail "unauthenticated request got $status in $mode mode" ;;
esac

# 2. Forged identity headers get nobody in.
read -r status _ < <(status_and_location \
  -H "X-Auth-Request-Email: $forged" -H "X-Forwarded-Email: $forged" -H "X-Forwarded-User: $forged" "$base/ssm")
[ "$status" != "200" ] || fail "a forged identity header was accepted"

echo "post-deploy check passed for $base ($mode mode)"
