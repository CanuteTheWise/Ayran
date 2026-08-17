"""Canonical hypothesis/tool equivalence for router dedup."""

from __future__ import annotations

from typing import Any

from ayran.context.ids import content_id
from ayran.hypotheses.builders import canonical_triple


def hypothesis_key(item: dict[str, Any]) -> str:
    triple = str(item.get("_triple") or "")
    if not triple:
        triple = canonical_triple(
            str(item.get("claim") or ""),
            str((item.get("target_entities") or ["state"])[0]),
            "unprivileged",
        )
    return content_id("dup", str(item.get("origin") or ""), triple)


def tool_key(capability_id: str, input_hash: str) -> str:
    return f"tool:{capability_id}:{input_hash}"
