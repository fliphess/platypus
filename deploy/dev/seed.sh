#!/bin/sh
# Fills the local AWS emulator with fake parameters and secrets for
# docker-compose. Safe to run again: existing items are left alone.
# PLATYPUS_SEED_BULK=500 also adds that many parameters, for trying the list
# pages and search with realistic volumes.
set -u

parameter() {
  aws ssm put-parameter --no-overwrite --name "$1" --type "$2" --value "$3" --description "$4" >/dev/null 2>&1 || true
}

secret() {
  aws secretsmanager create-secret --name "$1" --secret-string "$2" --description "$3" >/dev/null 2>&1 || true
}

parameter /payments/api/url SecureString "https://payments.example.com/api" "Payment provider endpoint"
parameter /payments/api/key SecureString "fake-payments-key-0001" "Payment provider API key"
parameter /payments/db/password SecureString "fake-db-password" "Payments database password"
parameter /search/endpoint String "https://search.example.com" "Search cluster endpoint"
parameter /search/replicas String "3" "Number of search replicas"
parameter /shared/feature-flags StringList "new-checkout,dark-mode" "Enabled feature flags"
parameter /shared/config SecureString '{"timeout":"30s","retries":"3"}' "Shared JSON configuration"

secret prod/payments/db '{"username":"payments","password":"fake-secret-password","host":"db.example.com"}' "Payments database credentials"
secret prod/search/api-token "fake-search-token" "Search API token"
aws secretsmanager create-secret --name prod/platform/rds --secret-string '{"username":"admin","password":"fake"}' \
  --description "Managed by Terraform" --tags Key=Terraform,Value=true >/dev/null 2>&1 || true
aws secretsmanager create-secret --name prod/legacy/certificate --secret-binary fileb:///etc/hostname \
  --description "A binary secret, which platypus doesn't support" >/dev/null 2>&1 || true

bulk="${PLATYPUS_SEED_BULK:-0}"
i=1
while [ "$i" -le "$bulk" ]; do
  n=$(printf '%04d' "$i")
  parameter "/bulk/service-$n/config" String "value-$i" "Bulk parameter $n for list and search testing"
  i=$((i + 1))
done

echo "seeded fake parameters and secrets"
# Deliberately long names: real deployments have them, so the lists should be
# judged with them present.
parameter /platform/payments/providers/external-billing/nested/configuration/api/credentials/primary/v2 SecureString "fake-long-value" "A very long parameter path, as real teams have them"
secret prod/platform/payments/providers/external-billing/nested/configuration/credentials/primary/v2 '{"note":"another very long name"}' "A very long secret path"
