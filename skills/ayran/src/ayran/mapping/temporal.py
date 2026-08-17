"""Temporal behavior map: deadlines, epochs, cooldowns, time-gated state."""

from __future__ import annotations

import json
from typing import Any

from ayran.context.ids import DEFAULT_CLUSTER_ID, DEFAULT_RUN_ID
from ayran.mapping.attack_surface import build_attack_surface
from ayran.mapping.source import TIME_RE
from ayran.mapping.types import map_summary_node

PINNED = "2026-08-12T12:00:00Z"


def _prop(node: dict[str, Any], name: str) -> str:
    for item in node.get("properties") or []:
        if item.get("name") == name:
            return str(item.get("value") or "")
    return ""


def build_temporal(
    *,
    cluster_id: str = DEFAULT_CLUSTER_ID,
    run_id: str = DEFAULT_RUN_ID,
    created_at: str = PINNED,
    source_text: str | None = None,
    source_units: list[dict[str, Any]] | None = None,
    slither_json: dict[str, Any] | None = None,
    locator: str = "target/src/Contract.sol",
) -> dict[str, Any]:
    surface = build_attack_surface(
        cluster_id=cluster_id,
        run_id=run_id,
        created_at=created_at,
        source_text=source_text,
        source_units=source_units,
        slither_json=slither_json,
        locator=locator,
    )
    blob = source_text or ""
    if source_units:
        blob = "\n".join(str(unit.get("source") or "") for unit in source_units)
    patterns = sorted({match.group(1) for match in TIME_RE.finditer(blob)})
    timed_functions = [
        _prop(node, "name")
        for node in surface["nodes"]
        if node.get("node_type") == "Function"
        and any(
            token in blob
            for token in ("block.timestamp", "block.number", "cooldown", "deadline", "unlock")
        )
    ]
    payload = json.dumps(
        {
            "cluster_id": cluster_id,
            "patterns": patterns,
            "timed_functions": sorted(set(timed_functions)),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    summary = map_summary_node(
        map_type="TemporalMap",
        cluster_id=cluster_id,
        run_id=run_id,
        created_at=created_at,
        payload=payload,
        extra={"pattern_count": len(patterns)},
    )
    fn_nodes = [node for node in surface["nodes"] if node.get("node_type") == "Function"]
    return {
        "map_type": "temporal",
        "cluster_id": cluster_id,
        "nodes": [*fn_nodes, summary],
        "edges": [],
        "patterns": patterns,
        "payload": json.loads(payload),
    }
