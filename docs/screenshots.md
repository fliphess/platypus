# Screenshots

Captured from the browser-test stack, so the data is demo data (example.com
addresses, fake values). They are 1280px wide, light theme, without the
test-mode banner.

Regenerate them with:

```
make screenshots
```

That runs the browser suite and writes `docs/images/*.png`.

## Overview

![The overview page](images/01-home.png)

## SSM parameters

![The parameter list](images/02-ssm-list.png)

Rows are one aligned table: name, type, state, note, last changed, and the
actions. The disclosure on the left opens the row.

![An expanded parameter row](images/03-ssm-row.png)

The expanded row shows the full path, description, type and tier, an explicit
link to the item's own page, and its note when it has one.

## Secrets

![A secret's page](images/04-secret-detail.png)

## Users

![The users list](images/05-users.png)

![A user's page](images/06-user-detail.png)

Teams and directly assigned policies are dropdown lines: attached entries are
one line each, "Add team" and "Add policy" add a line, and a dropdown only
offers entries that are not attached already.

## Teams

![The teams list](images/07-teams.png)

![A team's page](images/08-team-detail.png)

Members can be added with "Add member" and a dropdown of people not on the
team. The team's policies use the same editor as the user page.

## Policies

![The policies list](images/09-policies.png)

![The policy editor](images/10-policy-editor.png)

The rule editor previews what the rules match before saving.

## Audit trail

![The audit trail](images/11-audit.png)

## Documentation

![The in-app documentation](images/12-docs.png)
