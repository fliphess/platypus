# UI conventions

These guidelines keep the Platypus interface consistent across pages. Use the
shared components below when designing or updating a view, and document new
variants here so other contributors can reuse them.

## Page structure

Pages follow a common order: heading, toolbar, content, and pagination.
Place one primary action to the right of the title, and secondary actions
alongside the content they affect, such as a table row or card. Keep toolbar
controls in one row and content in a single table or stack of cards.

Navigation has two levels: the main tabs in the header and section links
within the admin area. Use toolbar controls for more specific views and
filters. Search and filters apply immediately, without a separate Filter
button.

Lists use pagination. Keep table widths within their cards, including dense
views, so columns remain visible without horizontal page scrolling. Views
within the same area share a page width.

## Interaction and content

- Keep content stable when revealing details. Use a dialog or update the
  relevant container without shifting unrelated controls. Reserve changes
  in page height for pagination.
- Reserve monospaced text for identifiers and values. Use badges to show
  state, and truncate long table text with the full text available in a
  tooltip.
- Confirm destructive actions in a dialog that explains the consequence.
- Give empty states a clear next step and associate validation errors with
  the affected field.
- Select people from known accounts when assigning access. Do not use
  free-text email fields for these assignments: a typo can grant access to
  the wrong person.
- Show status where users can act on it. Reserve full-width notices for
  conditions that prevent work, such as blocked access or errors.

## Shared components

| Component | Purpose and behaviour |
| --- | --- |
| Search | Debounced results update while typing, with the query reflected in the address bar. Enter also works without JavaScript. |
| Person picker | Type-ahead selection from known accounts, used when choosing a person. |
| Filter group | Date fields, selects, and text inputs in the toolbar; changes apply immediately. |
| Data table | Reference lists with aligned column types and actions on each row. See the column conventions below. |
| Form grid | Labels above inputs in a `.field` wrapper, with Save and Cancel at the bottom of the form card. |
| Pager | Previous and next controls with a count, preserving the current query. |
| Dialog | Confirmation of consequential actions and interactions that would otherwise disrupt the page. |
| Expandable record | A summary of a person or event, with the full record available on expansion. |
| Empty state | One muted sentence explaining the next step. |
| Statistic | A number and label linked to the relevant list, used on the overview. |
| Status page | Logo, title, one explanatory sentence, and one action for logged-out, blocked, no-access, disabled, locked, or not-found states. |

### Table columns

- Identifiers (`.mono-cell`, `.cell-name`) use monospaced text on one line.
  Truncate with an ellipsis and a `title` containing the full text.
- Timestamps (`.when`) do not wrap.
- State (`.state-cell`) uses badges on one line in a dedicated column.
- Descriptions truncate with the full text in a tooltip.
- Row actions (`.row-actions`) align to the right and sit vertically centred.
- Headers follow the same alignment as their cells. Use fixed column widths
  where needed to keep dense tables within their cards.

Use expandable records for longer text about people and events, such as
team membership, audit events, and orphaned notes. Summaries wrap without
clipping. Native `details` and `summary` elements provide expansion without
JavaScript. Tables suit reference lists of short identifiers, such as items,
teams, policies, and versions.

### Forms

Fields that could be mistaken for credentials use `autocomplete="off"` and
`data-1password-ignore` to avoid password-manager prompts. Clear fields when
a checkbox hides them so stale values cannot be submitted.

## Notifications

Use one status line below the header. When multiple states apply, show the
most important one; blocked access takes precedence over test mode. Style it
as a slim warning strip.

Transient confirmations, such as a saved change or an expired reveal, appear
as small toasts in the bottom right. They fade automatically and do not
reappear after a reload. Do not use banners, counters, cards, or notifications
to prompt visits to another page.

## Theme

Native controls follow the theme through `color-scheme`. Retain native date
pickers, scrollbars, and form controls. Inline `code` styling identifies
setting names and other identifiers within text. Test mode and blocked
access share the orange warning tone.

## JavaScript

htmx initialises content it swaps into the page. Application scripts that
insert content must call `htmx.process` on the inserted node so its htmx
behaviour is active.

## Reviewing interface changes

Reuse the shared components and document any new variants. Run the relevant
tests and browser suite, review captures in `e2e/shots/`, and refresh the
[documentation screenshots](screenshots.md) with `make screenshots` when
the documented interface changes. Use `make visual` to compare changes
against the committed visual baselines.
