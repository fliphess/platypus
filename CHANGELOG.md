# Changelog

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
