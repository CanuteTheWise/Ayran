"""Deterministic Crockford identifiers for M5 cognitive objects."""

from __future__ import annotations

import hashlib
import re

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_PREFIX = re.compile(r"^[a-z][a-z0-9]{1,11}$")
ZERO_HASH = "sha256:" + "0" * 64
PINNED_TIME = "2026-08-12T12:00:00Z"


def content_id(prefix: str, *parts: str) -> str:
    """Return a stable Identifier derived from canonical UTF-8 parts."""

    if not _PREFIX.fullmatch(prefix):
        raise ValueError(f"invalid identifier prefix: {prefix!r}")
    material = "\n".join(parts)
    digest = hashlib.sha256(material.encode("utf-8")).digest()
    value = int.from_bytes(digest[:17], "big") >> 6
    chars = ["0"] * 26
    for index in range(25, -1, -1):
        chars[index] = _ALPHABET[value & 31]
        value >>= 5
    return f"{prefix}_{''.join(chars)}"


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


DEFAULT_CLUSTER_ID = content_id("clu", "cluster:default")
DEFAULT_SCOPE_ID = "scp_01J00000000000000000000001"
DEFAULT_TARGET_ID = "tgt_01J00000000000000000000001"
DEFAULT_RUN_ID = "run_01J00000000000000000000001"
ROUTER_SEED_EVENT = content_id("evt", "router:seed")
