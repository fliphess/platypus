#!/usr/bin/env bash
# The stylesheet is assembled from small files, in filename order. Edit those
# (internal/web/static/css/*.css), then run `make css`; the served file stays
# one request and one content hash.
set -euo pipefail
cd "$(dirname "$0")/.."
cat internal/web/static/css/*.css > internal/web/static/style.css
