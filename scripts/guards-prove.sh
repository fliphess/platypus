#!/usr/bin/env bash
# Proves that the UI guards can fail: for each known regression, apply it to a
# clean tree, run the browser tests and require that the matching guard fails.
# A guard that cannot fail is worse than no guard, so this is the test of the
# tests. It rebuilds the stack once per mutant and restores the file each time.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain -- internal cmd database)" ]; then
	echo "guards-prove: commit your work first (it mutates tracked files)" >&2
	exit 1
fi

restore() { git checkout -- "$1"; }
trap 'git checkout -- internal cmd database 2>/dev/null || true' EXIT

# name | file | python replacement (old -> new) | text the failing guard prints
mutants=$(cat <<'TABLE'
utc|internal/web/render.go|viewer.User.Timezone != "local"|viewer.User.Timezone != "local-impossible"|the server rendered UTC|shows UTC or a stale time
pager-row|internal/web/static/css/06-audit-pager.css|  width: 2.1rem;\n  height: 2.1rem;\n  padding: 0;\n  line-height: 1;|  width: 2.1rem;\n  height: 3rem;\n  padding: 0;\n  line-height: 1;|the pager is not one aligned row
users-header|internal/web/templates/admin_users.html|<th>Status</th>||the users table has
items-header|internal/web/templates/browse.html|<th>Type</th>||the items table has
TABLE
)

while IFS='|' read -r name file old new expect; do
	[ -n "$name" ] || continue
	if [ -n "${GUARDS_PROVE_ONLY:-}" ] && [ "$name" != "$GUARDS_PROVE_ONLY" ]; then continue; fi
	echo "== mutant: $name ($file)"
	OLD="$old" NEW="$new" FILE="$file" python3 - <<'PY'
import os, pathlib
path = pathlib.Path(os.environ["FILE"])
src = path.read_text()
old = os.environ["OLD"].encode().decode("unicode_escape") if "\\n" in os.environ["OLD"] else os.environ["OLD"]
new = os.environ["NEW"].encode().decode("unicode_escape") if "\\n" in os.environ["NEW"] else os.environ["NEW"]
before = src.count(old)
if before != 1:
    raise SystemExit(f"guard-prove: {path}: {before} matches for the mutation")
path.write_text(src.replace(old, new))
PY
	# CSS lives in small source files now; mutate the source, then regenerate
	# the served stylesheet so the mutant is what the browser sees.
	case "$file" in
		internal/web/static/css/*) ./scripts/build-css.sh ;;
	esac
	if make e2e >/tmp/guards-prove.log 2>&1; then
		echo "MUTANT SURVIVED: $name — the guards did not notice" >&2
		restore "$file"
		exit 1
	fi
	# A regression can be caught by any of the guards that cover it; the
	# expectation lists the acceptable messages, separated by |.
	if ! grep -Eq "$expect" /tmp/guards-prove.log; then
		echo "MUTANT CAUGHT BY THE WRONG GUARD: $name (wanted: $expect)" >&2
		grep -E "^FAIL|problems:" /tmp/guards-prove.log | head -5 >&2
		restore "$file"
		exit 1
	fi
	echo "caught as expected: $expect"
	restore "$file"
	case "$file" in
		internal/web/static/css/*) ./scripts/build-css.sh ;;
	esac
done <<< "$mutants"

echo "all mutants caught"
