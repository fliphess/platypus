# Reporting a security issue

Platypus guards access to secrets, so reports are welcome and taken seriously.
This is a spare-time project: there is no company behind it, no security team
on call and no bug bounty. If you depend on platypus for anything serious,
plan your own monitoring and rollback around it.

## How to report

Open an issue on the repository tracker of the forge you found platypus on
(GitHub, GitLab, Codeberg: they all work the same for this). A merge request
with a fix is just as welcome as the report.

Please:

- Start the title with `security:`.
- Say which version or commit you tested.
- Describe how to reproduce it with harmless values. Don't put live secrets,
  real credentials or a weaponized exploit in a public report; if the problem
  only shows with sensitive details, say so and share them with whoever picks
  up the report, in private, once they ask.

## What happens next

Someone who maintains platypus will answer in the issue. Fixes land as regular
merge requests with a test; disclosure happens in the open, in the same issue.
There is no embargo process and no coordinated release train — releases come
when they are ready. Credit is given in the merge request unless you'd rather
stay unnamed.

## Scope

In scope: this repository, the container image built from it, and the Helm
chart.

Out of scope: weaknesses of a deployment that skips `deployment-checklist.md`
(for example `header` mode without the gateway stripping identity headers),
and the accepted risks listed in `threat-model.md`.
