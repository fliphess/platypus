# Runtime files

Platypus loads its HTML templates, static assets, and in-app documentation
from disk at startup. These files are distributed with the application and
can be customised without rebuilding the binary.

| Content | Environment variable | Default directory | Repository source |
| --- | --- | --- | --- |
| HTML templates | `PLATYPUS_TEMPLATES_DIR` | `templates` | `internal/web/templates/` |
| Static files served at `/static` | `PLATYPUS_STATIC_DIR` | `static` | `internal/web/static/` |
| In-app documentation | `PLATYPUS_DOCS_DIR` | `docs` | `internal/docs/pages/` |

The container image includes all three directories under `/app` and sets the
corresponding environment variables. Release archives place them alongside
the binary; the defaults work when you run Platypus from the extracted
directory. For a source build, set the variables to the repository paths
above or copy the directories alongside the binary and run it there.

Restart the application after changing these files.

## In-app documentation

Each page is a plain text file. Content is escaped before rendering; HTML
and Markdown are not interpreted.

- Use filenames such as `10-getting-started.txt`. The numeric prefix controls
  the order, and the remaining name becomes the URL: `/docs/getting-started`.
  The prefix is optional; names may contain lowercase letters, digits, and
  hyphens.
- Put the page title on the first line and separate paragraphs with blank
  lines. Short headings, `- ` bullet lists, and consecutive `term: text`
  entries provide basic structure.
- Files without a `.txt` extension are ignored. A `.txt` file with an invalid
  name prevents the documentation from loading.
- The configuration page, `90-configuration.txt`, is generated from
  `internal/config/vars.go` by `make generate`. CI checks that it is current.

To add organisation-specific guidance, copy the supplied pages into a
directory, add files such as `70-runbook.txt` or `80-on-call.txt`, and set
`PLATYPUS_DOCS_DIR` to that directory. The additional pages appear in the
documentation navigation.

## Templates and static assets

Custom templates must remain compatible with the data supplied by the
application handlers. Review them after each upgrade, as that contract can
change between versions.

For branding changes, copy the static directory, update the stylesheet or
`logo.svg`, and set `PLATYPUS_STATIC_DIR` to your copy. When changing styles
in this repository, edit `internal/web/static/css/*.css` and run `make css`
to rebuild `style.css`.

## File permissions

Templates and static assets control what users see and submit. Treat them
like the binary: mount them read-only and restrict write access to those
responsible for deploying the application.

Documentation pages are escaped text. They can be maintained by a wider
group, although their contents should still be reviewed for accuracy.
