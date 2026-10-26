# Changelog

## 0.1.1 — 2026-10-26

Hardening and polish after the first release.

### Changing behaviour

- A description is required when creating or editing a parameter or secret:
  it is what colleagues see in the list.
- Destructive actions now ask first: removing an authenticator app or a
  passkey, replacing recovery codes, disabling an account, removing someone
  from a team and deleting a team.
- A description form is tied to the description it showed, so two people
  editing the same item's metadata no longer overwrite each other silently.
- The Terraform management tags match regardless of case, and
  `docs/deployment-checklist.md` now explains the tag convention and the
  `ssm:ListTagsForResource` requirement behind it.

### Security and correctness

- Passkey ceremonies are single-use: a finish takes the ceremony in one
  statement, so two concurrent finishes cannot validate the same challenge.
- Issuing recovery codes locks the user, so two batches can't both stay valid;
  TOTP time steps are bound to the credential that was validated.
- Setting a user's policies or teams (or a team's policies) locks the row and
  reads the current set inside the transaction; the last-admin check happens
  under the admin lock.
- State changes and their audit events commit together: the block switch,
  sync requests, bootstrap completion and identity-provider group sync.
  Partial secret writes are recorded as such instead of vanishing.
- A sync that started before an edit can no longer put the old metadata back
  when it finishes (newer observations win).
- The audit CSV is built before the response starts, so a failed query can't
  append an HTML error page to a CSV; a worker job that panics is contained
  and retried instead of stopping the loop; a failed health listener closes
  its sibling listener.
- List pages load notes only for the rows they show, services bound page
  sizes and offsets themselves, and the audit user picker is capped.

### Packaging

- The chart can pin the image by digest, gives pods a startup probe budget
  and allows the EKS Pod Identity link-local egress path.
- `deploy/dev/seed.sh` accepts `PLATYPUS_SEED_BULK` to seed many parameters
  for trying lists and search.

## 0.1.0 — 2026-10-26

First release.

### Highlights

- A web UI for AWS SSM parameters and Secrets Manager secrets, so people can
  use them without AWS credentials.
- Values never leave the process as plain text unless a permitted user asks to
  reveal one, and every reveal is audited.
- Lists for parameters, secrets, the audit trail, users, teams, policies and
  orphaned notes, with aligned tables, search, real pagination and a shared
  rows-per-page control.
- The audit trail records every action, with filters, a live CSV export and a
  named resource for each event.
- Admin flows for users, teams and policies, including identity-provider
  group-linked teams, delegated admin mode, TOTP, passkeys and recovery codes.
- A headless bootstrap flow, a worker that syncs the catalog, and a Helm chart
  with examples for Ingress, Gateway API and EKS/External Secrets.
- Times are rendered by the server in the user's zone; no browser-side
  rewriting, so searches never flash UTC.

### Security notes

- Secret values exist only in `sensitive.Value`; errors, logs, audit details
  and the database never contain them.
- Every state-changing form carries CSRF; the CSP forbids inline scripts and
  styles; the independent audit copy is never sampled or silenced by the log
  level.
- The public test and example encryption keys are refused outside test mode,
  including equivalent base64 spellings.
- Secret contents are treated as opaque: whitespace is preserved.

### Deploying this release

Set a random 32-byte base64 `PLATYPUS_ENCRYPTION_KEY` and the database
connection; see `docs/deployment-checklist.md`. Migrations run at startup.
