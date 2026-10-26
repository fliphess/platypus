# Reporting a security issue

Security reports are welcome. Platypus is maintained in spare time, without
a dedicated security team, guaranteed response time, or bug bounty programme.
Production operators should maintain their own monitoring and rollback
procedures.

## Submit a report

Open an issue on the repository where you obtained Platypus. Include:

- A title beginning with `security:`.
- The affected version or commit.
- A description of the impact and steps to reproduce it using test data.

Keep live secrets, credentials, and weaponised exploits out of public
reports. If reproduction requires sensitive details, mention this in the
issue and arrange to share them privately when a maintainer responds.
A pull request with a proposed fix is also welcome.

## Response and disclosure

A maintainer will respond in the issue. Fixes are submitted through the
regular review process with a regression test, and disclosure takes place
in the issue. There is no embargo process or fixed release schedule.
Contributors receive credit in the fix unless they request otherwise.

## Scope

Reports may cover the application code, the published container image, or
the Helm chart.

Deployment misconfigurations covered by the [deployment
checklist](deployment-checklist.md), such as trusting identity headers
without stripping incoming headers at the gateway, are outside the project's
security scope. The [threat model](threat-model.md) documents accepted risks.
