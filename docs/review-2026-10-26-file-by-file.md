# Platypus file-by-file review — 2026-10-26

## Scope and method

This is the code-quality half of a release-readiness review, asked for as a
file-by-file pass: does the codebase have code smells, is it DRY, is it human
editable, is it tidy enough for a first release? It complements
`docs/review-2026-10-25.md` (security and correctness) and deliberately does
not repeat that report's findings.

Every hand-written Go file in `cmd/`, `internal/items`, `internal/item`,
`internal/catalog`, `internal/itemsync`, `internal/store` (all three
implementations), `internal/audit`, `internal/appstate`, `internal/sensitive`,
`internal/problem`, `internal/textclean`, `internal/lockout`,
`internal/ratelimit`, `internal/seal`, `internal/secrethash`,
`internal/logging`, `internal/health`, and the whole of `internal/web` and
`internal/authz` + `internal/access` (except `teams.go`, `policies.go`) was
read in full. The uncommitted screenshots work (Makefile, `e2e/browser.test.mjs`,
`e2e/run.sh`, `docs/ui.md`, `docs/screenshots.md`) was reviewed at diff level.

No application code, configuration, tests, or existing documentation was
changed by this review. This report is the only file created.

Parallel reviewers are covering the areas not read file-by-file here
(`internal/auth`, `session`, `mfa`, `bootstrap`, `config`, `database`,
`worker`, `app`, `docs`, the templates/static/e2e assets, delivery and infra,
and a status check of the previous review's R01–R31); their reports arrive
separately and should be read alongside this one.

## Validation performed

`make test-deps && make verify` on the working tree (including the
uncommitted screenshots work): **EXIT 0**. That covers `generate-check`
(generated code current), `vendored-check`, `go test -race -count=1 ./...`
(51 packages ok), `sqlfluff`, `css-check`, the full e2e browser suite
(including the new `documentation screenshots` step), and
`golangci-lint run ./...` — 0 issues.

## Overall assessment

The codebase is in genuinely good shape for a first release on this axis:

- **Small, single-purpose files.** The largest hand-written file is 875 lines
  (`handlers_admin_access.go`); most are under 300. No god objects.
- **DRY at the level that matters.** The invariants the project cares about
  are each centralized in one place: permission denals look like missing items
  (`items.authorize`), store errors map to user messages once
  (`items.storeError`), template rendering, paging, and form confirmation all
  have one shared implementation (`render.go`, `pagination.go`,
  `confirmChange`/`confirmAction`/`confirmSave`), and every store implements
  one contract verified by shared tests (`storetest`).
- **Human editable.** The route table reads like a table of contents; the
  authz package is pure and self-contained; comments explain *why* and still
  match the code; the prepare → apply → audit → refresh shape of item
  operations is learnable once and then predictable.

The findings below are small and localized. One is user-visible and worth
fixing before tagging (F1); F2–F4 are one tidy-up pull request in a single
file; the rest are nits to take or leave. Nothing here is structural, and
nothing argues for delaying a first release beyond the fixes the previous
review already prioritized.

## Findings

Severity reflects release readiness on the code-quality axis only.

### F1 — Low: restoring a secret shows no feedback (dead notice key)

**Evidence:** `internal/web/handlers_items.go:122` redirects with
`notice=restored`; the `notices` map in `internal/web/render.go:281-294` has
no `restored` entry, so the banner renders empty after a successful restore.

Why it matters: a user cancelling a scheduled deletion gets no confirmation
the destructive-looking state actually cleared — in a secrets tool, silence
after a security-relevant action is worse than a small DRY slip. It is also a
silent contract break between handlers and the notice registry, of exactly
the kind the project's "one inventory" conventions exist to prevent.

**Recommendation:** add a `restored` entry to `notices`. Consider a tiny test
or lint that every `notice=` key a handler emits exists in the map (the same
trick the route table already uses to guard `/admin`).

### F2 — Low: dead pagination fields left behind by the shared pager

**Evidence:** `internal/web/handlers_admin_access.go:32-33` (`usersData.
PrevPage/NextPage`, set at `:61-66`), `:444-445` (`teamsData.PrevLink/
NextLink`), `:660-661` (`policiesData.PrevLink/NextLink`). Only the `pager`
struct's own links are read (templates `partials.html:121,127`); these
per-page copies are written and never read.

Why it matters: dead fields tell the next editor that the lists have their
own paging controls. They don't. This is leftover from the migration to the
shared pager (a recent commit did exactly that).

**Recommendation:** delete the fields and their assignments.

### F3 — Low: needless forwarding wrappers for three preview handlers

**Evidence:** `internal/web/handlers_admin_access.go:234-388` defines
package-level `previewUserPolicies(w, r, s *Server)`, `previewTeamPolicies`,
`previewUserTeams`, and `:395-405` wraps each in a trivial method that only
forwards the arguments.

Why it matters: pure indirection. A reader must check both signatures to know
there is no second behavior; the file grows four function headers that carry
no information.

**Recommendation:** make the functions methods directly and delete the
wrappers.

### F4 — Medium (DRY): the selection diff is written three times

**Evidence:** `internal/web/handlers_admin_access.go:259-277`
(`previewUserPolicies`), `:308-322` (`previewTeamPolicies`), `:363-377`
(`previewUserTeams`) each build a `current` set, a `selected` set, and loop
twice to produce `added`/`removed`.

Why it matters: the three copies have already drifted subtly (the teams
variant skips group-linked memberships). A fourth editor copying the block
again is how the drift starts mattering. This is the one real duplication
found in the handlers.

**Recommendation:** one helper, e.g. `selectionDiff(current, selected
[]int64) (added, removed []int64)`, used by all three previews. F3 and F4 are
the same tidy-up commit.

### F5 — Low (DRY): the last-page arithmetic is repeated six times

**Evidence:** `internal/web/handlers_items.go:42`,
`internal/web/handlers_admin.go:86,154`, `internal/web/handlers_admin_access.
go:55,457,673` — all `int(max((total+int64(size)-1)/int64(size), 1))`.

**Recommendation:** a `lastPage(total int64, size int) int` helper next to
`newPager` in `pagination.go`.

### F6 — Low (DRY): audit filter mapping written three times

**Evidence:** `internal/audit/trail.go:41-49` (`List`), `:64-78`
(`pageParams`), `:80-91` (`countParams`) each copy the same five filter
fields plus the search LIKE-escaping.

Why it matters: a new filter field must be added in three places; forgetting
one produces a filter that silently works on one view and not another.

**Recommendation:** build the shared fields once (they are plain params
structs; a small `applyFilter` on each or a common builder) so the field list
exists once.

### F7 — Nit: three time-pointer helpers, two names, three behaviors

**Evidence:** `internal/catalog/catalog.go:275-288` — `timePtr` and `dbTime`
have identical bodies but different documented intents; `internal/store/
awsstore/awsstore.go:64` — `timePtr` is an identity function sharing the name
with catalog's zero-to-nil version.

Why it matters: the name `timePtr` means different things in adjacent
packages; a copy-paste between them compiles and behaves differently.

**Recommendation:** keep at most one zero-to-nil helper per package and give
them distinct names (e.g. `optionalTime` in catalog), or comment the awsstore
identity shim as a readability alias and drop its twin.

### F8 — Nit: mutation guard order varies between operations

**Evidence:** `internal/items/change.go:284-289` (`prepareUpdate` checks
`DeletedAt` after authorize and Terraform) vs `:349-351` (`Rollback` checks it
first) vs `internal/items/reveal.go:34-38` (reveal also checks it first).

Why it matters: not a bug today (the checks are independent), but "what order
do I check things in" is exactly the contract a new operation's author should
not have to reverse-engineer. The previous review made the same observation
about lifecycle consistency at a larger scale.

**Recommendation:** pick one documented order (suggest: entry → authorize →
terraform → deleted-state) and note it once on `entry`.

### F9 — Nit: the catalog leaks one generated type into handlers

**Evidence:** `internal/catalog/notes.go:56,62` return `[]db.Note` (sqlc
rows); `internal/web/handlers_admin.go:74-77` stores them straight into
template data. Everything else in the catalog wraps generated rows into its
own types.

**Recommendation:** a small `catalog.Note`-style wrapper (or reuse of the
existing one plus membership info) keeps the boundary uniform.

### F10 — Nit: `orphanedNotes` builds its summary twice

**Evidence:** `internal/web/handlers_admin.go:87-94`: computes a `summary`,
then overwrites it when the list is nonempty.

**Recommendation:** one branch-free expression, or fold the empty case into
the pager helper.

### F11 — Nit: slice-to-pointer idiom

**Evidence:** `internal/web/handlers_admin_access.go:62,65`:
`&[]int{pageNumber - 1}[0]`.

**Recommendation:** `p := pageNumber - 1; data.PrevPage = &p` (or drop the
fields entirely per F2).

## Notably good (preserve this)

- `internal/sensitive` — the redaction type covers every text-producing path
  Go and the two loggers have; the pointer-behind-box rationale is written
  down. This is the project's most important convention and it is impossible
  to use wrong by accident.
- `internal/authz` — pure, tiny, no I/O; "what users see and what is
  enforced can't drift apart" is achieved by construction.
- `internal/store/store.go` + `storetest` — the interfaces are documented
  contracts and the fake and the AWS adapter both run the same suite.
- `internal/store/awsstore/errors.go` — one place where AWS errors become
  safe, scrubbable errors.
- `internal/memstore` — faithful AWS semantics (version-stage movement,
  conflict windows) rather than a lazy fake; tests written against it mean
  something.
- `internal/audit` — `Record` vs `RecordBestEffort` encodes the fail-closed
  vs best-effort distinction in the type system, and reveal uses the right
  one.
- `internal/web/routes.go` — the route table reads like documentation, and
  the panic guard keeps the admin-mode invariant honest when routes are added.
- `internal/web/render.go` — the time-marker design (render, then substitute
  in the request's zone) removes an entire class of swap-time bugs.
- `internal/access/users.go` — at 526 lines still readable: transactional
  admin changes, a shared last-active-admin guard, and consistent
  before/after audit details.

## File-by-file verdicts

Verdicts are about code quality only. "Clean" means no changes suggested.

### cmd
| File | Lines | Verdict |
| --- | --- | --- |
| `platypus/main.go` | 80 | Clean. Clear usage, version stamping, signal handling, graceful Close. |

### Small foundations
| File | Lines | Verdict |
| --- | --- | --- |
| `sensitive/value.go` | 88 | Exemplary. |
| `problem/problem.go` | 57 | Clean, idiomatic. |
| `textclean/textclean.go` | 94 | Exemplary (Trojan-source aware, entity-loop stripping). |
| `lockout/lockout.go` | 57 | Clean. |
| `ratelimit/ratelimit.go` | 47 | Clean; MaxWindow invariant documented. |
| `seal/seal.go` | 74 | Clean; key-ID rotation explained. |
| `secrethash/secrethash.go` | 80 | Clean; OWASP parameters, self-describing hashes. |
| `logging/logging.go` | 25 | Clean. |
| `health/health.go` | 48 | Clean. |

### Domain core
| File | Lines | Verdict |
| --- | --- | --- |
| `item/item.go` | 139 | Clean shared vocabulary; AWS naming rules encoded with clear messages. |
| `items/items.go` | 213 | Clean; `authorize`/`storeError` centralize the core invariants. |
| `items/change.go` | 446 | Good prepare→apply→audit→refresh shape; F8 guard-order nit. |
| `items/detail.go` | 137 | Clean. |
| `items/reveal.go` | 92 | Clean; audit-before-return visible at the call site. |
| `items/undelete.go` | 39 | Clean; audit-before-reconciliation intent commented. |
| `items/value.go` | 95 | Clean JSON key-diff helper. |
| `items/list.go` | 99 | Clean; the audit-name convention (`/ssm?q=…`) is documented. |
| `catalog/catalog.go` | 288 | Clean; F7 nit. |
| `catalog/notes.go` | 80 | Clean; F9 nit. |
| `itemsync/itemsync.go` | 175 | Clean; database-clock reasoning written down. |

### Store layer
| File | Lines | Verdict |
| --- | --- | --- |
| `store/store.go` | 194 | Exemplary interface contracts. |
| `store/awsstore/awsstore.go` | 71 | Clean; F7 identity-helper nit. |
| `store/awsstore/errors.go` | 90 | Exemplary translation/scrubbing. |
| `store/awsstore/parameters.go` | 229 | Clean; the value-discarding access check is documented. |
| `store/awsstore/secrets.go` | 216 | Clean. |
| `store/memstore/memstore.go` | 483 | Clean; faithful AWS semantics. |
| `store/storetest/storetest.go` | 304 | Good shared contract; no clear-description scenario yet (previous review R13 gap, still open). |

### Audit and state
| File | Lines | Verdict |
| --- | --- | --- |
| `audit/audit.go` | 154 | Exemplary. |
| `audit/trail.go` | 200 | Good; F6 DRY nit. |
| `audit/actions.go` | 81 | Clean. |
| `appstate/appstate.go` | 94 | Clean. |

### Web layer
| File | Lines | Verdict |
| --- | --- | --- |
| `routes.go` | 154 | Exemplary. |
| `middleware.go` | 375 | Clean; every middleware documented, ordering clear. |
| `render.go` | 469 | Clean; time-marker design well explained (F1 evidence lives here). |
| `server.go` | 133 | Clean; content-hashed asset version. |
| `viewer.go` | 40 | Clean. |
| `pagination.go` | 158 | Clean shared component. |
| `handlers_items.go` | 426 | Clean; F1. |
| `handlers_admin.go` | 219 | Clean; F5, F10. |
| `handlers_admin_access.go` | 875 | Needs one tidy pass: F2, F3, F4, F5, F11. Otherwise well organized by entity; CRUD via `userAction`/`teamAction` wrappers is a nice pattern. |
| `handlers_adminmode.go` | 128 | Clean. |
| `handlers_auth.go` | 103 | Clean. |
| `handlers_bootstrap.go` | 75 | Clean. |
| `handlers_me.go` | 110 | Clean. |
| `handlers_security.go` | 260 | Clean; one `securityAccess` gate for all factor changes. |

### Authorization and access
| File | Lines | Verdict |
| --- | --- | --- |
| `authz/authz.go` | 154 | Exemplary. |
| `authz/pattern.go` | 68 | Clean, tiny. |
| `access/access.go` | 55 | Clean; strict email parsing. |
| `access/subject.go` | 60 | Clean; row→rule mapping with policy-name error context. |
| `access/users.go` | 526 | Clean despite size; see "notably good". |

## Uncommitted work (screenshots feature)

Reviewed at diff level only (the frontend reviewer covers it in depth). The
`make screenshots` target and the `DOCS_SHOTS=1` e2e step follow the existing
patterns (gated, uses `step()`, mounts `docs/images` into the container), and
the step ran green inside `make verify`. Two small smells worth noting for
whoever finishes it: the `03-ssm-row` shot is taken manually outside the
`shoot()` helper (duplicating its strip-and-wait logic), and the fixed
150/200 ms waits are the same magic numbers the rest of the suite uses — if
the suite grows more of them, a shared `settle()` helper would pay for
itself.

## Coverage map

Read file-by-file here: everything listed in the tables above.

Delegated to the parallel reviewers (read their reports before concluding
release readiness): `internal/access/teams.go`, `access/policies.go`,
`internal/auth/*`, `internal/session/*`, `internal/mfa/*`,
`internal/bootstrap/*`, `internal/config/*`, `internal/database/*`,
`internal/db/user.go`, `internal/docs/*`, `internal/worker/*`,
`internal/app/*`, `internal/web/templates/*`, `internal/web/static/*` (app.js,
theme.js, css), `e2e/*`, `database/*` (migrations, queries, sqlc config),
`charts/*`, `.github/*`, `scripts/*`, `deploy/*`, root files (Makefile,
Dockerfile, compose files, lint configs), `docs/*` beyond this file, and the
status check for R01–R31 from the 2026-10-25 review.

## Verdict

On the code-quality axis — smells, duplication, editability, tidiness —
platypus is **ready for a first release** after F1 (one line) and ideally one
tidy-up commit for F2–F4, all confined to `internal/web`. F5–F11 are optional
polish and can wait. The release decision overall should still wait for the
parallel reports, especially the R01–R31 status check: the previous review's
high-severity findings (R01 above all) are the real gate, not anything found
here.

For maintainability after release, the one habit worth adopting from F1 and
F6 is the route-table trick: when a registry and its users live apart (notice
keys, audit filter fields), make a test or a panic tie them together, the way
`routes()` already does for admin-mode routes.
