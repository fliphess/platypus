# UI conventions

How platypus looks and behaves, so every change fits the whole. Read this
before touching a template. The rules are short on purpose; when a change
can't follow them, the design is wrong, not the rules.

## Principles

1. One skeleton per page: a page head, a toolbar, content, a pager — in that
   order. Nothing renders outside it.
2. Two navigation levels, ever: the tabs in the header, and the section
   links inside the admin area. Anything finer is a control in a toolbar,
   never another row of tabs.
3. One component per job, defined once, listed below. A new variant needs a
   reason written here.
4. No layout jumps: content that appears on demand opens in a dialog or
   swaps inside its own container. The page only changes height through
   pagination.
5. Every list paginates. Monospaced type is for identifiers and values only.
   Badges show state, not decoration. Long text truncates instead of
   stretching layouts.
6. No nagging: no banners, counters or cards that ask for a visit. State is
   shown where you act on it. The only full-width interruptions are the
   block notice and errors, because they stop action rather than request it.
7. Destructive actions confirm in a dialog that names the consequence. Empty
   states say what to do next. Errors name the field they are about.
8. People are picked from lists of known accounts, never typed as free-text
   email addresses: a typo in a typed address hands access to the wrong
   person.

## The page skeleton

- **Page head**: the title, with the page's one primary action at the right.
  Secondary actions live where they act (a row, a card), not here.
- **Toolbar**: the search box, view switches (segmented links) and filters,
  in one row. Everything in a toolbar applies immediately; there is no
  Filter button anywhere.
- **Content**: one table or one stack of cards. Tables carry row actions,
  quiet and right-aligned, on the row's line.
- **Pager**: below content, carrying the current query.

## Components

- `search`: the toolbar search box. Live: results refresh while typing
  (debounced), the address bar follows, Enter still works without scripts.
- `picker`: a type-ahead over known accounts (a datalist over users). Used
  wherever a person is chosen. Never an open email field.
- `filter group`: date inputs, selects and text inputs in the toolbar that
  apply on change.
- `data table`: the shared table spec. Column types carry their rules:
  identifiers (`.mono-cell`, `.cell-name`) are monospaced, one line, ellipsis
  with the full text in a tooltip; moments (`.when`) never wrap; state
  (`.state-cell`) is badges on one line in their own column; descriptions
  clip with a tooltip; row actions (`.row-actions`) sit right-aligned on the
  row's middle. Headers align with cells because they share the types.
  Anything an ellipsis clips carries a `title` with the full text. Tables
  FIT their card (fixed column widths where a table is dense): the page
  never scrolls sideways and no column is pushed out of sight. Every view of
  an area shares one page width.
- `form grid`: labels above their own input, inside a `.field` wrapper;
  actions (Save/Cancel) live at the foot of the form's card, never floating
  between cards. Fields whose purpose could look like a login carry
  `autocomplete="off"` and `data-1password-ignore`. Fields revealed by a
  checkbox are emptied when hidden, so stale values can't submit.
- `pager`: previous/next with a count, preserving the query.
- `dialog`: for confirmations with consequences and for anything that would
  otherwise resize the page.
- `dropout rows`: the shape for people and events (users, team members,
  audit trail, orphaned notes). The summary line is a row of facts that wraps
  freely — nothing is ever clipped — and clicking the line opens the complete
  record underneath (native `details`/`summary`, no scripts). Tables are for
  reference lists of short identifiers (items, teams, policies, versions); a
  free-text or people column belongs in a dropout row instead.
- `empty state`: one muted sentence that says what to do next.
- `stat`: a number with a label, linked to its list. Used on the home page.
- `status page`: logo, title, one sentence, one action. Used for logged out,
  blocked, no access, disabled, locked, not found.

## Notifications

There is one status line under the header, never a stack of banners: the
most important state wins (blocked above test mode). It is a slim strip in
the warning tone, not a card. Transient confirmations ("saved", "admin mode
off", "value hidden again") are small toasts in the bottom right that fade
out by themselves and never replay on reload. Anything that asks the user
to go look at another page is forbidden.

## Theme

Native controls (date pickers, scrollbars, form controls) follow the theme
via `color-scheme`; nothing ships a custom-styled native control. Inline
code (`code`) is for identifiers and setting names: a quiet chip, never a
heading. Test mode and blocked state both use the orange warning tone.

## Scripting rules

htmx binds the content it swaps itself; anything this app's own scripts
insert into the page must call `htmx.process` on the inserted node, or it
sits inert. Password managers must not open on fields that are not
credentials: fields get `autocomplete="off"` and `data-1password-ignore`
when their name or purpose could look like a login.

## Process

Every interface change reuses this inventory (or adds a justified entry to
it), keeps the tests and browser run green, and refreshes its screenshot in
`e2e/shots/` so the result is visible without running the app.

Screenshots of every view: [screenshots.md](screenshots.md).
