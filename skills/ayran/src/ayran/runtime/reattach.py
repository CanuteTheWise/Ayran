"""Idempotent-reattach health probe for pinned engagement runs.

Night-1 defect D1 fix: ``ayran start`` used to rotate the per-run bearer token
unconditionally on every reattach, stranding any live sidecar that still held
the previous token in memory while every client read the new one from disk.
Rotation is now permitted only after this probe fails to reach a healthy
service using the CURRENT token file contents.
"""

from __future__ import annotations

import time
from pathlib import Path

from ayran.api.client import AyranClient

PROBE_TIMEOUT_SECONDS = 4.0
_PROBE_SETTLE_SECONDS = 0.25


def probe_socket_healthy(sock: Path, token_file: Path) -> bool:
    """True only when a live service answers ``run.ping`` with the current token.

    Any failure mode — missing socket, missing/unreadable token, refused
    connection, timeout, auth mismatch, malformed reply — means "not healthy
    for reattach". A TRANSIENT failure (busy daemon, cold scheduler) must
    never trigger a rotation by itself, so a failed probe is always re-checked
    once before the caller may conclude the guard is gone.
    """

    if not sock.exists() or not token_file.is_file():
        return False
    try:
        token = token_file.read_bytes()
    except OSError:
        return False
    if _probe_once(sock, token):
        return True
    time.sleep(_PROBE_SETTLE_SECONDS)
    return _probe_once(sock, token)


def _probe_once(sock: Path, token: bytes) -> bool:
    try:
        client = AyranClient(sock, token_bytes=token, timeout=PROBE_TIMEOUT_SECONDS)
        result = client.call("run.ping")
    except Exception:  # any failure means not healthy; never leak past prepare
        return False
    return isinstance(result, dict) and bool(result)
