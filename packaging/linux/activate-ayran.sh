#!/bin/sh
# Atomically point current at a versioned prefix after health checks.
set -eu
PREFIX="${1:?prefix}"
VERSION="${2:?version}"
printf '%s\n' "$PREFIX/versions/$VERSION" > "$PREFIX/current.tmp"
mv "$PREFIX/current.tmp" "$PREFIX/current"
