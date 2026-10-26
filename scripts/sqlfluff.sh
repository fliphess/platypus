#!/usr/bin/env bash
# Lints the sqlc queries with sqlfluff (Postgres dialect).
#
# sqlc's placeholders (@name, sqlc.arg('name'), sqlc.narg('name')) and their
# casts are not valid Postgres, so the queries are copied to a temporary
# directory with every placeholder (including a trailing cast) replaced by a
# harmless string literal — valid SQL that keeps joins, lists and subqueries
# lintable without inventing "= NULL" style warnings. The lint checks shape
# and style; placeholder types are sqlc's job.
set -euo pipefail

cd "$(dirname "$0")/.."
sqlfluff_image="${SQLFLUFF_IMAGE:-sqlfluff/sqlfluff:3.4.0}"

tmp="$(mktemp -d)"
# The sqlfluff image runs as a non-root user, while mktemp creates a 0700
# directory: without this it cannot read the mounted queries on Linux CI.
chmod 755 "$tmp"
trap 'rm -rf "$tmp"' EXIT

python3 - "$tmp" <<'PY'
import pathlib, re, sys

out = pathlib.Path(sys.argv[1])
source = pathlib.Path("database/queries")
# sqlc placeholders first, then the shorter @name form; a trailing cast on
# the placeholder goes with it (the placeholder's type is sqlc's business).
# sqlc accepts both sqlc.narg('name') and sqlc.narg(name).
named = re.compile(r"sqlc\.n?arg\(['\"]?([A-Za-z0-9_]+)['\"]?\)(::[A-Za-z0-9_\[\]]+)?")
at = re.compile(r"@([A-Za-z0-9_]+)(::[A-Za-z0-9_\[\]]+)?")

for path in sorted(source.glob("*.sql")):
    text = path.read_text()
    text = named.sub("'x'", text)
    text = at.sub("'x'", text)
    (out / path.name).write_text(text)
PY

docker run --rm -v "$tmp":/queries -v "$PWD/.sqlfluff":/.sqlfluff -w /queries \
  --entrypoint sqlfluff "$sqlfluff_image" lint --dialect postgres .
