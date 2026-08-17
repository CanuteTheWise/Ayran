"""Shared M3 test identities and a durable in-window scope fixture."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
RUN_ID = "run_01J00000000000000000000001"
TARGET_ID = "tgt_01J00000000000000000000001"
TARGET_KEY = "sha256:" + "a" * 64
TARGET_IDENTITY = {
    "target_id": TARGET_ID,
    "source_tree_hash": "sha256:" + "d" * 64,
    "scope_id": "scp_01J00000000000000000000001",
    "commit": "1" * 40,
}


def scope_value() -> dict[str, Any]:
    value = cast(
        dict[str, Any],
        json.loads(
            (ROOT / "fixtures" / "contracts" / "scope-manifest" / "valid" / "minimal.json").read_text(
                encoding="utf-8"
            )
        ),
    )
    value["valid_from"] = "2020-01-01T00:00:00Z"
    value["valid_until"] = "2099-01-01T00:00:00Z"
    value["run_id"] = RUN_ID
    value["allowed_tools"] = []
    value["rules"] = [
        {
            "rule_id": "rul_01J00000000000000000000001",
            "effect": "allow",
            "action": "read_source",
            "resource": "target/src",
        },
        {
            "rule_id": "rul_01J00000000000000000000002",
            "effect": "allow",
            "action": "compile_local",
            "resource": "target/src",
        },
        {
            "rule_id": "rul_01J00000000000000000000003",
            "effect": "allow",
            "action": "graph_read",
            "resource": ".",
        },
        {
            "rule_id": "rul_01J00000000000000000000004",
            "effect": "allow",
            "action": "graph_write",
            "resource": ".",
        },
    ]
    value["integrity"] = {
        "algorithm": "sha256",
        "canonicalization": "rfc8785",
        "content_hash": "sha256:" + "0" * 64,
        "excluded_fields": ["integrity.content_hash"],
    }
    return value
