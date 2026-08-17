"""M0-compatible prefixed ULID allocation."""

from __future__ import annotations

import os
import threading
import time

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_lock = threading.Lock()
_last_ms = -1
_last_random = 0


def _encode(value: int, length: int) -> str:
    output = ["0"] * length
    for index in range(length - 1, -1, -1):
        output[index] = _ALPHABET[value & 31]
        value >>= 5
    return "".join(output)


def new_ulid() -> str:
    global _last_ms, _last_random
    with _lock:
        now_ms = time.time_ns() // 1_000_000
        if now_ms == _last_ms:
            _last_random = (_last_random + 1) & ((1 << 80) - 1)
        else:
            _last_ms = now_ms
            _last_random = int.from_bytes(os.urandom(10), "big")
        return _encode(now_ms, 10) + _encode(_last_random, 16)


def new_id(prefix: str) -> str:
    if not (2 <= len(prefix) <= 12) or not prefix.isalnum() or not prefix[0].isalpha():
        raise ValueError("identifier prefix must be 2-12 lowercase alphanumeric characters")
    if prefix != prefix.lower():
        raise ValueError("identifier prefix must be lowercase")
    return f"{prefix}_{new_ulid()}"

