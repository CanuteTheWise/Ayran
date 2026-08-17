#!/bin/sh
# Remove only receipt-listed Ayran paths. Never remove external Prime or tools.
set -eu
RECEIPT=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --receipt) RECEIPT="$2"; shift ;;
    *) echo "usage: uninstall-ayran.sh --receipt <path>" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$RECEIPT" ] || { echo "receipt required" >&2; exit 2; }
PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 || PYTHON=python
exec "$PYTHON" -m ayran.cli release uninstall --receipt "$RECEIPT"
