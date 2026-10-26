# Screenshots

A tour of the Platypus interface, captured with demonstration data. Images
use the light theme at 1280 pixels wide, with the test-mode banner hidden.
All addresses and values are examples.

## Overview

![The overview page](images/01-home.png)

## SSM parameters

![The parameter list](images/02-ssm-list.png)

The list shows each parameter's name, type, state, note, and last change.
Expand a row to view its details.

![An expanded parameter row](images/03-ssm-row.png)

Expanded rows show the full path, description, type, tier, and note, with a
link to the parameter's page.

## Secrets

![A secret's page](images/04-secret-detail.png)

## Users

![The users list](images/05-users.png)

![A user's page](images/06-user-detail.png)

Manage team membership and directly assigned policies from the user's page.
"Add team" and "Add policy" offer entries that have not already been assigned.

## Teams

![The teams list](images/07-teams.png)

![A team's page](images/08-team-detail.png)

"Add member" lets you select an account that is not already on the team.
Team policies use the same assignment controls as the user page.

## Policies

![The policies list](images/09-policies.png)

![The policy editor](images/10-policy-editor.png)

Preview which items each rule matches before saving a policy.

## Audit trail

![The audit trail](images/11-audit.png)

## Documentation

![The in-app documentation](images/12-docs.png)

## Updating these images

Run the browser suite with screenshot capture enabled:

```sh
make screenshots
```

The command writes the images to `docs/images/`.
