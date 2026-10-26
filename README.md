# Platypus

A web UI to manage SSM parameters and Secrets Manager secrets, so people don't
need AWS access to change them. Only platypus has the AWS permissions; people
get exactly the access their policies grant, and everything they do is in the
audit trail.

- Login with your identity provider: platypus logs people in itself (OIDC), or
  works behind a login proxy that sends a signed token or a trusted header.
- Policies grant `list`, `create`, `edit` and `reveal` on name patterns, to
  teams or to single users. Values are hidden unless a policy allows revealing.
- Admins confirm admin mode with a passkey or authenticator app. Admin mode
  doesn't give access to values.
- Values never reach the database, the logs or error messages.

The in-app docs explain how to use it. `docs/` holds the threat model, the
deployment checklist and how to report a security issue.

## Run it locally

You need Docker. Nothing else: no AWS account, no login provider.

```sh
docker compose up --build
make dev-bootstrap-token    # in another terminal
```

Open <http://admin.localhost:8090>, enter the token, set up an authenticator
app and finish the setup. <http://editor.localhost:8090> and
<http://nobody.localhost:8090> are two more users. A small nginx stands in for
the gateway and sets the identity header per hostname; the AWS emulator
(ministack) holds fake parameters and secrets from `deploy/dev/seed.sh`.

To try `oidc` mode, with Dex as the identity provider, add `127.0.0.1 dex` to
`/etc/hosts` (your browser has to reach Dex by the name platypus uses), run
`docker compose --profile oidc up --build` and open <http://localhost:8094>.
Log in as `olivia@example.com` with password `platypus-dev`.

## Install

- Image: `ghcr.io/fliphess/platypus`, amd64 and arm64.
- Chart: `helm install platypus oci://ghcr.io/fliphess/charts/platypus --version <version> -f my-values.yaml`
  (or `charts/platypus` from this repository).
- Binaries: every release has `platypus_<version>_<os>_<arch>.tar.gz` for linux
  and darwin, amd64 and arm64, with checksums. Unpack it and run `./platypus web`;
  the templates, static files and docs pages stay next to the binary.
- From source: with Go 1.26 or newer, `make build`, or cross-compile with
  `GOOS` and `GOARCH`: `GOOS=linux GOARCH=arm64 go build ./cmd/platypus`.
  See `docs/assets.md` for the runtime files a bare binary needs.

## Develop

```sh
make test-deps   # Postgres and the AWS emulator in Docker
make test        # all tests, with the race detector
make lint        # golangci-lint and govulncheck
make generate    # after changing SQL queries or configuration variables
make smoke       # the whole stack from an empty database
make e2e         # browser tests (Playwright in Docker), including passkeys and oidc mode
```

Layout:

- `cmd/platypus`: the binary: `web`, `worker`, `reset-bootstrap`.
- `internal/app`: wires everything together.
- `internal/web`: handlers, middleware, templates and static files (htmx).
- `internal/items`: list, view, reveal, create, edit, roll back, notes.
- `internal/authz`: the permission rules (pure, no I/O).
- `internal/access`: users, teams, policies.
- `internal/mfa`, `internal/lockout`, `internal/session`, `internal/bootstrap`: admin mode and setup.
- `internal/store`: the AWS interface; `awsstore` (SDK) and `memstore` (tests) both pass `storetest`.
- `internal/catalog`, `internal/itemsync`, `internal/worker`: the metadata cache and the jobs that fill it.
- `internal/audit`: the audit trail.
- `internal/sensitive`: the type every value lives in; it never prints its contents.
- `internal/docs/pages`, `internal/web/templates`, `internal/web/static`: the runtime files the binary loads from disk.
- `database/migrations/updates`: Flyway migrations. `database/migrations/bootstrap`: database and roles for container Postgres.
- `database/queries`: SQL for sqlc, generated into `internal/db`.
- `charts/platypus`: the Helm chart; no dependencies.

Configuration is environment variables only; `internal/docs/pages/90-configuration.txt`
lists all of them and is generated from `internal/config`. The interface is read
from disk at startup, not compiled in: templates (`internal/web/templates`),
static files (`internal/web/static`), docs pages (`internal/docs/pages`). Running
the binary outside Docker means setting `PLATYPUS_TEMPLATES_DIR`,
`PLATYPUS_STATIC_DIR` and `PLATYPUS_DOCS_DIR`, or keeping the three directories
next to it; `docs/assets.md` explains how it works.

## Deploy

The Helm chart in `charts/platypus` has no dependencies. You need:

- Postgres. Create the database and an application role (see
  `database/migrations/bootstrap/init.sql` for what that looks like) and run the
  Flyway migrations in `database/migrations/updates` before each deploy.
- An AWS role for platypus (IRSA or EKS Pod Identity) with SSM and Secrets
  Manager access; platypus never needs delete permissions.
- A login, set with `PLATYPUS_AUTH_MODE`: `oidc` (platypus logs people in with
  your identity provider; works behind any Ingress), `signed-header` (a login
  proxy such as Google IAP, Cloudflare Access or Pomerium sends a signed token)
  or `header` (a login proxy such as oauth2-proxy sets a header, which the
  gateway must strip from incoming requests). `docs/deployment-checklist.md`
  has the details; read `docs/threat-model.md` too.

```sh
helm install platypus charts/platypus -f my-values.yaml
```

`charts/platypus/ci/` has example values: a minimal setup, oidc mode behind an
Ingress, and EKS with kgateway, oauth2-proxy and External Secrets. After every
deploy, `scripts/post-deploy-check.sh <url> <mode>` checks that unauthenticated
requests and forged identity headers don't get in.

Images will be published to `ghcr.io/fliphess/platypus`; there are no releases
yet. Build your own with `docker build .` until then.

## License

MIT, see `LICENSE`. To report a vulnerability, see `docs/security.md`.
