# Notes for people and agents working on platypus

`docs/` is the repository documentation. Read `docs/threat-model.md` before
changing anything security-relevant; `docs/deployment-checklist.md` is what a
deployment needs around platypus, `docs/security.md` how to report an issue,
`docs/assets.md` how the runtime files work.

The interface is not embedded in the binary. The in-app documentation pages
live in `internal/docs/pages/` (plain text), the HTML templates in
`internal/web/templates/` and the static files in `internal/web/static/`.
Platypus loads all three from disk at startup; `PLATYPUS_DOCS_DIR`,
`PLATYPUS_TEMPLATES_DIR` and `PLATYPUS_STATIC_DIR` say from where.

## Rules that keep platypus safe

- Values (parameter and secret contents) only ever live in `sensitive.Value`.
  Call `Reveal()` only where a value must go to AWS or to the browser of a user
  allowed to see it (`internal/web/handlers_items.go`, `revealData`). Never put
  values in logs, errors, audit details or the database. The canary tests in
  `internal/items` and `internal/web` fail when one leaks.
- Every permission check goes through `authz.Subject.Can`. Items a user can't
  list must look exactly like items that don't exist.
- Every action records an audit event. A reveal is recorded before the value is
  returned, and not returned when recording fails.
- AWS errors pass through `awsstore.translate`, which scrubs values from them.
- Free text from users goes through `textclean.Clean` before it is stored.
- Templates use `html/template` only. No inline scripts or styles: the
  Content-Security-Policy forbids them.

## Conventions

- Errors meant for the user are `problem` errors; anything else shows a generic
  message with the request id.
- Database access goes through sqlc (`database/queries` -> `internal/db`); run
  `make generate` after changing queries or configuration variables, and
  `make sqlfluff` to lint the queries themselves.
- Migrations are Flyway files in `database/migrations/updates`, named
  `V<yyyymmdd>.<hhmm>__<description>.sql`. Keep them backwards compatible with
  the previous release: web pods of both versions run during a rollout.
- Configuration is environment variables only, declared in
  `internal/config/vars.go`.
- Styles are assembled: edit `internal/web/static/css/*.css` (one concern per
  file) and run `make css`. `style.css` is generated; `make css-check` fails
  when it is stale.
- `make verify` is the gate: generated code, vendored files, tests, sqlfluff,
  the stylesheet check and the browser suite.
- Tests: `make test-deps && make test`. Database tests get a fresh database
  each (`dbtest.New`); AWS tests run against ministack.

## Releasing

CI on `main` must be green. Bump `version` and `appVersion` in
`charts/platypus/Chart.yaml` in the release commit, then tag `vX.Y.Z` and push
the tag: the release workflow builds the binaries and images for every
platform, publishes the chart and opens the release with the artifacts
attached. Binaries get their version from `-ldflags "-X main.version=<tag>"`.
