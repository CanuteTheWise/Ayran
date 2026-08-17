#!/bin/sh
# Ayran Linux installer. Offline. Never mutates externally owned Prime or tools.
set -eu

KIND=""
PRIME=""
PREFIX="${AYRAN_PREFIX:-$HOME/.local/ayran}"
DRY=""
SOURCE="."

usage() {
  echo "usage: install-ayran.sh --layer --prime <path> [--prefix DIR] [--dry-run]"
  echo "       install-ayran.sh --complete [--prefix DIR] [--dry-run]"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --layer) KIND=layer ;;
    --complete) KIND=complete ;;
    --prime) PRIME="$2"; shift ;;
    --prefix) PREFIX="$2"; shift ;;
    --source) SOURCE="$2"; shift ;;
    --dry-run) DRY=--dry-run ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

if [ -z "$KIND" ]; then
  usage
  exit 2
fi

if [ "$KIND" = "layer" ] && [ -z "$PRIME" ]; then
  echo "Layer install requires --prime <path>" >&2
  exit 2
fi

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  PYTHON=python
fi

ARGS="release install --$KIND --prefix $PREFIX"
if [ -n "$PRIME" ]; then
  ARGS="$ARGS --prime $PRIME"
fi
if [ -n "$SOURCE" ]; then
  ARGS="$ARGS --source $SOURCE"
fi
if [ -n "$DRY" ]; then
  ARGS="$ARGS $DRY"
fi

# shellcheck disable=SC2086
exec "$PYTHON" -m ayran.cli $ARGS
