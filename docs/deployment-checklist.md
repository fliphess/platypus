# Deployment checklist

What has to be in place around platypus before it runs safely. Most of it lives outside this repository:
in your gateway, AWS account, database and cluster. Read `threat-model.md` for why each item matters.

## Login

Choose how people log in with `PLATYPUS_AUTH_MODE`. Every mode checks the email domain
(`PLATYPUS_ALLOWED_EMAIL_DOMAINS`).

**oidc**: platypus logs people in itself. Simplest to deploy: any Ingress will do.

1. Register platypus at your identity provider (Google, Okta, Entra ID, Keycloak, Dex, ...) with redirect
   URL `https://<your platypus>/auth/callback`, and set `PLATYPUS_OIDC_ISSUER`, `PLATYPUS_OIDC_CLIENT_ID`
   and `PLATYPUS_OIDC_CLIENT_SECRET`.
2. Choose `PLATYPUS_SESSION_IDLE_TIMEOUT` and `PLATYPUS_SESSION_MAX_AGE`. With `PLATYPUS_OIDC_PROMPT=login`,
   people enter their credentials again after an idle logout instead of being signed back in silently.

**signed-header**: a login proxy sends a signed token that platypus verifies.

1. Set `PLATYPUS_SIGNED_HEADER`, `PLATYPUS_SIGNED_HEADER_JWKS_URL`, `PLATYPUS_SIGNED_HEADER_ISSUER` and
   `PLATYPUS_SIGNED_HEADER_AUDIENCE` from your proxy's documentation. Examples:
   - Google IAP: header `X-Goog-Iap-Jwt-Assertion`, keys `https://www.gstatic.com/iap/verify/public_key-jwk`,
     issuer `https://cloud.google.com/iap`, audience `/projects/<number>/global/backendServices/<id>`.
   - Cloudflare Access: header `Cf-Access-Jwt-Assertion`, keys
     `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`, issuer `https://<team>.cloudflareaccess.com`,
     audience your application's AUD tag.
   - Pomerium: header `X-Pomerium-Jwt-Assertion`, keys `https://<authenticate URL>/.well-known/pomerium/jwks.json`,
     issuer and audience the route's host.
   - oauth2-proxy passing the ID token (`--pass-authorization-header`): header `Authorization`, keys, issuer
     and audience of your identity provider and oauth2-proxy's client ID.
   AWS ALB's `x-amzn-oidc-data` uses its own key format and is not supported yet.
2. The login lifetime is the proxy's: configure it there.

**header**: a login proxy sets a header with the email address, which platypus trusts.

1. Put a login proxy in front of platypus (for example oauth2-proxy) that only lets authenticated users
   through and sets the identity header platypus reads (`PLATYPUS_IDENTITY_HEADER`, default
   `X-Auth-Request-Email`). To link teams to identity-provider groups, also set `PLATYPUS_GROUPS_HEADER`
   (oauth2-proxy: `X-Auth-Request-Groups`); it must be stripped like the identity header (it is in the
   list below), and whoever manages those groups then decides the members of linked teams.
2. Strip the identity headers from every incoming request **before** authentication runs, so nobody can send
   their own. With Envoy-based gateways (kgateway, Envoy Gateway, Istio) that is an early request header
   modification on the listener; a header modifier on the route runs too late and also removes the header
   the login proxy sets. The headers oauth2-proxy uses:
   - `x-auth-request-user`, `x-auth-request-email`, `x-auth-request-preferred-username`,
     `x-auth-request-groups`, `x-auth-request-access-token`
   - `x-forwarded-user`, `x-forwarded-email`, `x-forwarded-preferred-username`, `x-forwarded-groups`,
     `x-forwarded-access-token`
3. Make sure the platypus hostname is covered by the login proxy's cookie domain and redirect allowlist.
4. The login lifetime is the proxy's: configure it there (for oauth2-proxy `--cookie-expire`).

**All modes**

5. Keep platypus internal (VPN or private network) if you can.
6. After every deploy, run `scripts/post-deploy-check.sh https://<your platypus> <mode>`: it fails when
   unauthenticated requests or forged identity headers get through.

## AWS

7. An IAM role for platypus, assumed through IRSA or EKS Pod Identity (no access keys). Platypus never needs
   to delete anything. A starting point:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "Parameters",
         "Effect": "Allow",
         "Action": [
           "ssm:DescribeParameters",
           "ssm:GetParameter",
           "ssm:GetParameters",
           "ssm:GetParameterHistory",
           "ssm:PutParameter",
           "ssm:AddTagsToResource",
           "ssm:ListTagsForResource"
         ],
         "Resource": "*"
       },
       {
         "Sid": "Secrets",
         "Effect": "Allow",
         "Action": [
           "secretsmanager:ListSecrets",
           "secretsmanager:DescribeSecret",
           "secretsmanager:GetSecretValue",
           "secretsmanager:PutSecretValue",
           "secretsmanager:UpdateSecret",
           "secretsmanager:CreateSecret",
           "secretsmanager:ListSecretVersionIds",
           "secretsmanager:UpdateSecretVersionStage",
            "secretsmanager:RestoreSecret",
           "secretsmanager:TagResource"
         ],
         "Resource": "*"
       },
       {
         "Sid": "Encryption",
         "Effect": "Allow",
         "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
         "Resource": "<the KMS keys of your parameters and secrets>"
       }
     ]
   }
   ```

   Narrow `Resource` if platypus should only manage part of the account. Items platypus can't access are
   hidden in the UI.
8. Optionally a separate role for live tests in CI, limited to a few test parameters.

## Database

9. Postgres 13 or newer (the migrations create the trusted `pg_trgm` extension as the database owner).
10. A database, a migrations role that owns it, and an application role with read-write access but no DDL
    rights. `database/migrations/bootstrap/init.sql` shows this for a container database.
11. Run the Flyway migrations in `database/migrations/updates` before each deploy. `afterMigrate.sql` grants
    the application role its rights and keeps it from updating the audit trail.
12. Back up the database: it holds users, policies, second factors and the audit trail (never values).
12a. Platypus checks the database server's certificate (`PLATYPUS_DB_SSLMODE=verify-full`, the default). If a
    public authority doesn't sign it, as with RDS, give platypus the authority's certificate: put the RDS
    bundle (`https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`) in a ConfigMap and set
    `databaseCA.configMap` in the chart. `require` encrypts without checking who answers; avoid it.

## Secrets for platypus itself

13. `PLATYPUS_DB_USERNAME`, `PLATYPUS_DB_PASSWORD` and `PLATYPUS_ENCRYPTION_KEY` (32 random bytes, base64:
    `openssl rand -base64 32`) in a Kubernetes Secret, ideally filled by External Secrets.

## Kubernetes

**Gateway error pages.** The chart deploys no proxy of its own: it renders an
`HTTPRoute` or an `Ingress` for the gateway you already run. When platypus'
pods are restarting, whoever answers the request shows that error page — an
ingress controller's default 502 looks like "nginx", which confuses people.
Point your gateway at a friendly unavailable page instead: for nginx ingress
that is `controller.custom-http-errors` plus a default backend, for Envoy-based
gateways a local reply template. The local docker-compose proxy already serves
`deploy/dev/50x.html` when the app is down, as an example.

14. Restrict `exec`, `attach`, `port-forward`, ephemeral containers and reading secrets in the platypus
    namespace to a small group: anyone who can exec into a platypus pod has platypus's AWS and database access.
15. Keep the NetworkPolicy from the chart: only the gateway reaches the web pods. Narrow where platypus may
    connect with `networkPolicy.postgresTo` and `networkPolicy.httpsTo` if your network allows.

## Files

16. The binary reads its interface from disk: the templates (`PLATYPUS_TEMPLATES_DIR`), the static files
    (`PLATYPUS_STATIC_DIR`) and the in-app docs (`PLATYPUS_DOCS_DIR`). The container image and the release
    archives ship them next to the binary; if you run the binary on its own, keep the three directories with
    it or point the variables elsewhere. See `assets.md` for what each directory holds and how to extend
    the docs with your own pages.

## First start

17. Read the bootstrap token from SSM (`PLATYPUS_BOOTSTRAP_TOKEN_PARAM`) and complete the setup in the
    browser. See `internal/docs/pages/50-setup-and-recovery.txt`.
