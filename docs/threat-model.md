# Threat model

Platypus holds the AWS permissions that people used to have themselves. That
makes it a single point that must not leak values or let people do more than
their policies allow. This file lists what we defend against and how; keep it
in step with the code.

## Assets

1. Parameter and secret values in AWS.
2. The ability to change them (and so the configuration of every service).
3. The policies deciding who may do what.
4. The audit trail.
5. The catalog in the database: the name, description and tags of every
   parameter and secret, never values. A map of what exists, so it is kept as
   carefully as the rest of the database.

## Trust boundaries

- **Browser to platypus**: preferably over a private network or VPN, through a
  gateway or ingress. A NetworkPolicy lets only that gateway reach the web pods.
- **Login** (`PLATYPUS_AUTH_MODE`):
  - `header`: a login proxy sets the identity header; the gateway strips it from
    incoming requests. Platypus trusts it and can't verify it.
  - `signed-header`: a login proxy sends a signed token; platypus verifies the
    signature, issuer, audience and expiry against the proxy's public keys.
  - `oidc`: platypus runs the login itself (authorization code flow with PKCE,
    state and nonce) and keeps it in its own session.
- **Platypus to AWS**: IRSA (later Pod Identity) role with full SSM and
  Secrets Manager access except delete. Policies in platypus decide per user.
- **Platypus to Postgres**: application role without DDL rights and without
  UPDATE on the audit trail, over TLS that checks the server's certificate
  (`verify-full` by default).

## Threats and defences

1. **Someone pretends to be another user.**
   `header` mode relies on the gateway stripping and setting the header and on
   the NetworkPolicy; `signed-header` and `oidc` mode verify a signature
   themselves and fail closed. In every mode: an email domain allow-list,
   unverified email addresses refused, and the post-deploy check
   (`scripts/post-deploy-check.sh`) failing the pipeline when unauthenticated
   requests or forged headers get through. In `oidc` mode a fresh session is
   started at every login (no session fixation), and the return address after
   the login is limited to local paths (no open redirect).
2. **An unattended, unlocked screen.**
   In `oidc` mode a login ends after `PLATYPUS_SESSION_IDLE_TIMEOUT` and
   `PLATYPUS_SESSION_MAX_AGE`, and `PLATYPUS_OIDC_PROMPT=login` asks for
   credentials again; revealed values hide after a few seconds; admin mode ends
   by itself. In the proxy modes the proxy's login lifetime applies.
3. **A user reads or changes more than their policies allow.**
   Every operation goes through `authz.Subject.Can`; lists filter in SQL on the
   user's patterns; items a user can't list look like items that don't exist;
   create never overwrites; changes carry the version they started from.
4. **A stolen login session becomes admin.**
   Admin mode needs a second factor (TOTP or passkey) and ends by itself.
   Changing factors needs admin mode once a factor exists. Five failed attempts
   lock the account. Admin mode grants no access to values.
5. **Values leak through logs, errors, caches or the database.**
   Values only live in `sensitive.Value`, which never prints its contents; AWS
   errors are scrubbed (`awsstore.translate`); pages are `no-store`; values are
   never in URLs; canary tests search logs, database, audit trail and pages.
6. **Cross-site attacks (CSRF, XSS, clickjacking).**
   SameSite=Strict session cookie plus a per-session CSRF token and Go's
   cross-origin protection on every state change; `html/template` escaping;
   strict CSP without inline code or eval; free text cleaned on save;
   `frame-ancestors 'none'`.
7. **Bulk reading of values by a legitimate user.**
   Reveals are rate limited per user and every reveal is audited before the
   value is returned.
8. **Covering tracks.**
   The audit trail can't be changed from the UI; the database role can't update
   it; every event is also logged to stdout, for a log store outside platypus.
   Pruning is a manual admin action that is itself recorded. The migrations
   role owns the table and could change it; it is only used by Flyway.
9. **The bootstrap is hijacked.**
   The token is only readable through SSM in the AWS account; it expires; it is
   stored hashed; wrong guesses count towards the lockout.
10. **Platypus is used to reach items it shouldn't.**
    Items platypus can't access in AWS are hidden; deleting isn't possible at
    all; binary secrets can't be overwritten.
11. **Supply chain.**
    Few dependencies; htmx vendored with a checksum that CI checks;
    govulncheck, golangci-lint (gosec) and a check that generated code is up to
    date in CI; GitHub Actions and tool versions pinned; image built from
    scratch with only the binary, its runtime files (templates, static files,
    in-app docs) and CA certificates.

## Accepted risks

- Anyone who can exec into a platypus pod (or read its Kubernetes secrets) has
  platypus's AWS and database access. Kubernetes RBAC must keep that group
  small (`deployment-checklist.md`, Kubernetes). The bootstrap reset relies on this.
- An admin who has never set up a second factor enrolls the first one on trust
  (whoever holds their login session). Admins are added by other admins, and
  every enrollment is audited.
- When the login provider or the gateway is down, platypus is down; AWS admins
  use AWS directly.
- SSM and Secrets Manager have no conditional writes: a change landing between
  platypus's version check and its write (one round trip) is not detected.
- The access check for SSM String parameters (`GetParameter` without
  decryption) receives the value from AWS; it is discarded unread.
- Creating an item fails when the name exists, so someone allowed to create
  under a pattern learns which names exist there, even ones they can't list.
  Any create has to fail on an existing name; the AWS message is scrubbed.
- A description change to a secret and a value change from someone else can
  cross in the same round trip as above (Secrets Manager's UpdateSecret has no
  version condition either).
- Users are identified by email address. Whoever controls the identity
  provider could give a departed admin's address to someone else, who would get
  that account. The identity provider's admins are trusted anyway.
- The bootstrap token stays in SSM after use (platypus has no delete rights).
  It is useless then: the database marks it used.
- The migrations role owns the audit table and could change it. It is only
  used by Flyway; the copy of every event in the logs is the independent record.
- The reveal limit counts per calendar minute, so up to twice the limit fits
  around the turn of a minute. Every reveal is audited.
- A team linked to an identity-provider group makes whoever manages that group
  an indirect policy admin: they decide its members, and the team carries the
  policies. Only platypus admins create links (audited), and the docs say to
  link only groups managed by people trusted with those policies.
- The templates and static files are read from disk at startup
  (`PLATYPUS_TEMPLATES_DIR`, `PLATYPUS_STATIC_DIR`): whoever can write them
  changes the interface as if they could change the source. Mount them
  read-only, like the binary itself. The in-app docs pages are plain text and
  escaped; they carry no such power.
