#!/bin/sh
# Verify a Layer or Complete archive without network access.
set -eu
PATH_ARG=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --path) PATH_ARG="$2"; shift ;;
    *) echo "usage: verify-install.sh --path <bundle>" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$PATH_ARG" ] || { echo "bundle path required" >&2; exit 2; }
PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 || PYTHON=python
exec "$PYTHON" -m ayran.cli release validate --path "$PATH_ARG"
