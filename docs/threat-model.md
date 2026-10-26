# Threat model

Platypus uses shared AWS permissions to manage parameters and secrets on
behalf of its users. It must protect those values and enforce each user's
policies on every operation. This document describes the assets, trust
boundaries, protections, and accepted risks of that design.

## Assets

1. Parameter and secret values in AWS.
2. Permission to change values and the configuration of services that use them.
3. Policies governing access to parameters and secrets.
4. The audit trail.
5. The metadata catalog: names, descriptions, and tags of parameters and
   secrets. Although it contains no values, it reveals which resources exist
   and requires the same protection as the rest of the database.

## Trust boundaries

- **Browser to Platypus:** traffic passes through a gateway or ingress,
  preferably over a private network or VPN. A NetworkPolicy restricts access
  to the web pods to that gateway.
- **Authentication** (`PLATYPUS_AUTH_MODE`):
  - `header`: an authentication proxy sets the identity header, and the
    gateway strips it from incoming requests. Platypus trusts the header
    and cannot verify it independently.
  - `signed-header`: an authentication proxy sends a signed token. Platypus
    verifies its signature, issuer, audience, and expiry against the proxy's
    public keys.
  - `oidc`: Platypus handles OpenID Connect authentication using the
    authorisation code flow with PKCE, state, and nonce, then maintains its
    own session.
- **Platypus to AWS:** an IAM role assumed through IRSA or EKS Pod Identity
  grants SSM and Secrets Manager permissions without delete permissions.
  Platypus policies determine each user's access within that scope.
- **Platypus to PostgreSQL:** the application role has no DDL rights or
  permission to update audit events. TLS verifies the server's certificate
  with `verify-full` by default.

## Threats and defences

1. **Identity spoofing.**
   Header authentication depends on the gateway stripping and setting identity
   headers, and on the NetworkPolicy preventing direct access. Signed-token
   and OIDC authentication verify signatures and reject invalid tokens. An
   email domain allowlist applies in every mode, and unverified email claims
   are rejected. The post-deployment check (`scripts/post-deploy-check.sh`)
   fails if unauthenticated requests or forged headers are accepted. OIDC
   starts a fresh session at each login to prevent session fixation and
   restricts return addresses to local paths to prevent open redirects.
2. **Unattended sessions.**
   OIDC sessions expire according to `PLATYPUS_SESSION_IDLE_TIMEOUT` and
   `PLATYPUS_SESSION_MAX_AGE`. Setting `PLATYPUS_OIDC_PROMPT=login` requests
   credentials again at login. Revealed values are hidden automatically, and
   admin mode expires. In proxy authentication modes, the proxy controls the
   login lifetime.
3. **Access beyond a user's policies.**
   Every operation checks `authz.Subject.Can`. Lists are filtered in SQL
   against the user's name patterns, and items the user cannot list return
   the same response as missing items. Creation never overwrites an existing
   item. Updates include the version on which the edit was based.
4. **Administrative access through a stolen session.**
   Admin mode requires a second factor (TOTP or a passkey) and expires
   automatically. Once a factor is enrolled, changing factors requires admin
   mode. Five failed attempts lock the account. Admin mode does not grant
   access to values.
5. **Value disclosure through logs, errors, caches, or the database.**
   Values are held in `sensitive.Value`, which does not print its contents.
   AWS errors are scrubbed by `awsstore.translate`. Responses use `no-store`,
   and values never appear in URLs. Canary tests check logs, the database,
   audit events, and pages for unintended disclosure.
6. **Cross-site attacks (CSRF, XSS, clickjacking).**
   State changes are protected by a `SameSite=Strict` session cookie, a
   per-session CSRF token, and Go's cross-origin protection. Templates use
   `html/template` escaping, free text is cleaned on save, and the Content
   Security Policy prohibits inline code and `eval`. The policy includes
   `frame-ancestors 'none'` to prevent framing by other sites.
7. **Bulk reading by an authorised user.**
   Reveals are rate limited per user. Each reveal is audited before the value
   is returned.
8. **Audit tampering.**
   The interface cannot modify audit events, and the application database
   role cannot update them. Each event is also written to stdout for
   collection by an independent log store. Pruning requires an explicit admin
   action and is itself audited. The migrations role owns the audit table and
   can modify it; this role is reserved for Flyway.
9. **Unauthorised initial setup.**
   The bootstrap token is retrieved through SSM in the AWS account. It expires,
   is stored as a hash, and incorrect guesses count towards account lockout.
10. **Access beyond the application's AWS permissions.**
    Items that Platypus cannot access in AWS are hidden. The application does
    not support deletion and cannot overwrite binary secrets.
11. **Supply chain compromise.**
    The application has a small dependency set. CI checks the vendored htmx
    checksum, runs govulncheck and golangci-lint with gosec, and verifies
    generated code. GitHub Actions and tool versions are pinned. The image
    is built from scratch and contains only the binary, runtime files, and
    CA certificates.

## Accepted risks

- Anyone who can execute commands in a Platypus pod or read its Kubernetes
  Secrets has the application's AWS and database access. Restrict that group
  through Kubernetes RBAC (see the [deployment checklist](deployment-checklist.md#kubernetes)).
  Bootstrap recovery relies on this level of access.
- An admin's initial second-factor enrollment trusts whoever controls their
  login session at that time. Existing admins add new admins, and every
  enrollment is audited.
- An identity-provider or gateway outage makes Platypus unavailable. AWS
  administrators must use AWS directly during the outage.
- SSM and Secrets Manager do not support conditional writes. A concurrent
  change between Platypus's version check and its write can go undetected.
  A secret description update can also overlap with another user's value
  update because `UpdateSecret` has no version condition.
- Checking access to an SSM String parameter with `GetParameter` without
  decryption still returns its value from AWS. Platypus discards that value
  without reading it.
- Creation must fail when a name already exists. A user with create permission
  can therefore discover existing names within their allowed pattern, even
  for items they cannot list. AWS error messages are scrubbed.
- Users are identified by email address. An identity-provider administrator
  who reassigns a former admin's email address gives its new owner access to
  that account. Identity-provider administrators are part of the trust boundary.
- The bootstrap token remains in SSM after use because Platypus has no delete
  permissions. The database marks it as used, so it cannot be reused.
- The migrations role owns the audit table and can modify it. This role is
  reserved for Flyway; copies of events in external logs provide an
  independent record.
- Reveal limits apply per calendar minute. Up to twice the configured limit
  can occur across a minute boundary. Every reveal is still audited.
- Linking a team to an identity-provider group delegates control over team
  membership, and therefore its policies, to that group's managers. Only
  Platypus admins can create these links, and the action is audited. Link
  only groups whose managers are trusted to grant the associated access.
- Anyone who can modify templates or static assets can change the interface
  as if they could change application code. Mount the directories configured
  by `PLATYPUS_TEMPLATES_DIR` and `PLATYPUS_STATIC_DIR` read-only. In-app
  documentation is escaped plain text and cannot execute code.
