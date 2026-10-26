# Deployment checklist

Use this checklist when preparing a production deployment. It covers the gateway,
AWS account, database, and Kubernetes configuration that Platypus depends on.
The [threat model](threat-model.md) explains the security boundaries and accepted risks.

## Login

Choose an authentication mode with `PLATYPUS_AUTH_MODE`. Every mode checks the email domain
(`PLATYPUS_ALLOWED_EMAIL_DOMAINS`).

### OpenID Connect (`oidc`)

Platypus handles sign-in through your identity provider. This mode works behind a standard Ingress.

1. Register Platypus with your identity provider (for example, Google, Okta, Entra ID, Keycloak, or Dex) with redirect
   URL `https://<your-platypus-host>/auth/callback`, and set `PLATYPUS_OIDC_ISSUER`, `PLATYPUS_OIDC_CLIENT_ID`
   and `PLATYPUS_OIDC_CLIENT_SECRET`.
2. Choose `PLATYPUS_SESSION_IDLE_TIMEOUT` and `PLATYPUS_SESSION_MAX_AGE`. With `PLATYPUS_OIDC_PROMPT=login`,
   users enter their credentials again after an idle logout instead of being signed back in silently.

### Signed token (`signed-header`)

An authentication proxy sends a signed token that Platypus verifies.

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
2. Configure the session lifetime in the authentication proxy.

### Trusted header (`header`)

An authentication proxy sets a header containing the user's email address. Platypus trusts this header,
so the gateway must prevent clients from supplying it directly.

1. Configure an authentication proxy (for example, oauth2-proxy) to accept only authenticated users
   and set the identity header Platypus reads (`PLATYPUS_IDENTITY_HEADER`, default
   `X-Auth-Request-Email`). To link teams to identity-provider groups, also set `PLATYPUS_GROUPS_HEADER`
   (oauth2-proxy: `X-Auth-Request-Groups`); it must be stripped like the identity header (it is in the
   list below). Group managers control membership of linked teams and therefore access to their policies.
2. Strip the identity headers from every incoming request **before** authentication runs to prevent users
   from supplying their own identity. With Envoy-based gateways (kgateway, Envoy Gateway, Istio), use an early request header
   modification on the listener; a header modifier on the route runs too late and also removes the header
   the login proxy sets. The headers oauth2-proxy uses:
   - `x-auth-request-user`, `x-auth-request-email`, `x-auth-request-preferred-username`,
     `x-auth-request-groups`, `x-auth-request-access-token`
   - `x-forwarded-user`, `x-forwarded-email`, `x-forwarded-preferred-username`, `x-forwarded-groups`,
     `x-forwarded-access-token`
3. Include the Platypus hostname in the proxy's cookie domain and redirect allowlist.
4. Configure the session lifetime in the authentication proxy (for oauth2-proxy, use `--cookie-expire`).

### All authentication modes

1. Use a private network or VPN where possible.
2. After every deployment, run `scripts/post-deploy-check.sh https://<your-platypus-host> <mode>`: it fails when
   unauthenticated requests or forged identity headers are accepted.

## AWS

1. Create an IAM role for Platypus, assumed through IRSA or EKS Pod Identity, without static access keys.
   Platypus does not require delete permissions. Use the following policy as a starting point:

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

   Narrow `Resource` if Platypus should only manage part of the account. Items Platypus cannot access are
   hidden in the UI.
2. Tag everything Terraform manages with `Terraform=true` and leave `ssm:ListTagsForResource` in the policy.
   Platypus refuses to change the value or description of tagged items, so a change made in the UI cannot be
   silently undone by the next `terraform apply`. `PLATYPUS_TERRAFORM_TAGS` lists the tags that count;
   keys and values match without regard to case, so `terraform=TRUE` counts too.
   Secret tags come with every sync. SSM tags are read on first use and cached, and a parameter AWS does not
   let Platypus tag-read looks untagged: it stays editable and Terraform would undo a change made there.
   Keeping `ssm:ListTagsForResource` and tagging consistently is what makes the guard work.
3. If running live AWS tests in CI, use a separate role limited to test parameters.

## Database

1. Provide PostgreSQL 13 or newer. The migrations create the trusted `pg_trgm` extension as the database owner.
2. Create a database, a migrations role that owns it, and an application role with read-write access but no
   DDL rights. See the [container database setup](../database/migrations/bootstrap/init.sql) for an example.
3. Run the Flyway migrations in `database/migrations/updates` before each deployment. `afterMigrate.sql`
   grants the application role its permissions and prevents it from updating the audit trail.
4. Back up the database. It holds users, policies, second factors, and audit events, but no parameter or
   secret values.
5. Keep certificate verification enabled with `PLATYPUS_DB_SSLMODE=verify-full` (the default). Supply a CA
   bundle when needed. For RDS, put the bundle from
   `https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem` in a ConfigMap and set
   `databaseCA.configMap` in the chart. Avoid `require`: it encrypts the connection without verifying the
   server's identity.

## Application credentials

Store `PLATYPUS_DB_USERNAME`, `PLATYPUS_DB_PASSWORD`, and `PLATYPUS_ENCRYPTION_KEY` in a Kubernetes Secret,
ideally populated by External Secrets. Generate the encryption key with `openssl rand -base64 32`.

## Kubernetes

The chart creates an `HTTPRoute` or `Ingress` for your existing gateway.
Configure an unavailable page there so users receive a clear message during
restarts. For nginx ingress, use `controller.custom-http-errors` with a default
backend; for Envoy-based gateways, use a local reply template. The local
Docker Compose proxy uses [50x.html](../deploy/dev/50x.html) as an example.

1. Restrict `exec`, `attach`, `port-forward`, ephemeral containers, and access to Kubernetes Secrets in the
   Platypus namespace to a small group. Anyone who can execute commands in a pod has the application's
   AWS and database access.
2. Retain the chart's NetworkPolicy so only the gateway can reach the web pods. Restrict outbound access
   with `networkPolicy.postgresTo` and `networkPolicy.httpsTo` where your network supports it.

## Files

Include the templates (`PLATYPUS_TEMPLATES_DIR`), static assets (`PLATYPUS_STATIC_DIR`), and in-app
documentation (`PLATYPUS_DOCS_DIR`). The container image and release archives include these files.
For a standalone binary, supply the directories and configure their paths as described in
[runtime files](assets.md). Mount templates and static assets read-only.

## First start

Read the bootstrap token from SSM (`PLATYPUS_BOOTSTRAP_TOKEN_PARAM`) and complete setup in the browser.
See [setup and recovery](../internal/docs/pages/50-setup-and-recovery.txt) for the commands and recovery
procedures.
