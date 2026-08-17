"""Per-run bearer token creation, file-descriptor inheritance, and verification.

Blueprint §3.7 requires socket ownership plus a per-run bearer **in an
inherited file descriptor**, never a prompt-visible token.  The launcher opens
the token file once, marks its descriptor inheritable, and passes the numeric
fds to the worker child environment.  The worker writes only the fd number —
never the token value — into its process environment (which is visible to the
supervisor's env fingerprint without ever materializing the secret).

Verification is constant-time and never logs the secret.
"""

from __future__ import annotations

import hmac
import os
import secrets
import stat
from pathlib import Path

from ayran.graph.canonical import fsync_directory

TOKEN_BYTES = 32
_TOKEN_ENV_PREFIX = "AYRAN_TOKEN_FD_"


class TokenError(ValueError):
    pass


def create_token(root: Path, *, run_id: str) -> Path:
    """Create a fresh per-run token file with 0o600 on the ext4 runtime dir."""

    root.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(TOKEN_BYTES)
    path = root / f"{run_id}.token"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, token.encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    fsync_directory(root)
    return path


def open_inheritable(path: Path) -> tuple[int, bytes]:
    """Open a token file for descriptor inheritance; return (fd, expected)."""

    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        status = os.fstat(fd)
        if not stat.S_ISREG(status.st_mode):
            raise TokenError("token path must resolve to a regular file")
        if os.name != "nt" and stat.S_IMODE(status.st_mode) != 0o600:
            raise TokenError("token path must be mode 0o600")
        if status.st_uid != getattr(os, "getuid", lambda: os.getpid())():
            raise TokenError("token path must be owned by the current owner")
        expected = os.read(fd, TOKEN_BYTES * 2)
    except OSError as error:
        os.close(fd)
        raise TokenError(str(error)) from error
    os.set_inheritable(fd, True)
    return fd, expected


def inherited_fd_env(fd: int, run_id: str) -> dict[str, str]:
    """Return the numeric-fd environment block written for the child."""

    return {f"{_TOKEN_ENV_PREFIX}{run_id}": str(fd)}


def verify_token(fd_or_token: int | bytes, expected: bytes) -> bool:
    """Compare the presented value with the expected token in constant time.

    Accepts either a numeric file descriptor (re-reads the token) or the raw
    token bytes.  Comparison is constant-time; the token value is never logged.
    """

    if isinstance(fd_or_token, int):
        fd = os.dup(fd_or_token)
        try:
            if os.lseek(fd, 0, os.SEEK_SET) < 0:
                return False
            presented = os.read(fd, TOKEN_BYTES * 2)
        finally:
            os.close(fd)
        return hmac.compare_digest(presented, expected)
    if isinstance(fd_or_token, bytes):
        return hmac.compare_digest(fd_or_token, expected)
    return False
