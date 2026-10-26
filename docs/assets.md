# Runtime files: templates, static files and the in-app docs

The platypus binary is only code. Everything people see is read from disk at
startup: the HTML templates, the static files and the documentation pages
shown inside the app. Nothing is compiled in, so a deployment can change any
of it without rebuilding.

| What | Environment variable | Default | Source in this repository |
| --- | --- | --- | --- |
| HTML templates | `PLATYPUS_TEMPLATES_DIR` | `templates` | `internal/web/templates/` |
| Static files (`/static`) | `PLATYPUS_STATIC_DIR` | `static` | `internal/web/static/` |
| In-app docs | `PLATYPUS_DOCS_DIR` | `docs` | `internal/docs/pages/` |

The container image ships all three under `/app` with the variables set. A
release archive ships them next to the binary, so the defaults work from the
directory you unpacked it in.

## The in-app docs

One text file per page, plain text only: no markup, no HTML. Everything is
escaped before it reaches the browser.

- The file name sets the order and the address: `10-getting-started.txt`
  becomes the page `/docs/getting-started`. Numbers sort, they are not shown.
- The first line is the title. Blank lines separate paragraphs.
- Only files named like `<number-><lowercase-and-dashes>.txt` are read;
  everything else in the directory (a `README.md`, notes, anything) is ignored.
- `90-configuration.txt` is generated from the code (`make generate`) and
  checked by CI; edit `internal/config/vars.go`, not the file itself.

To add pages for your own organisation, don't rebuild anything: point
`PLATYPUS_DOCS_DIR` at a directory with the platypus pages plus your own —
`70-runbook.txt`, `80-on-call.txt`, whatever your people need. The docs tab
shows them in the same list.

## Templates and static files

Overriding these is possible (that is why they are on disk) but they are part
of the application: the templates must provide the fields the handlers expect,
and that contract changes between versions. If you only want another colour or
your own logo, copy the directory, change `style.css` or `logo.svg`, and set
the variable to your copy; re-check after every upgrade.

## Safety

The templates are code-equivalent: whoever can write `PLATYPUS_TEMPLATES_DIR`
can change what the app shows and submits. Treat these directories like the
binary itself — mounted read-only, writable only by whoever ships the release.
Docs pages, in contrast, are inert text and safe to hand to wider groups.
