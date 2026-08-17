"""Subprocess worker used by the real WSL/ext4 SIGKILL test harness."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ayran.graph import AppendCommand, AppendItem, GraphStore
from ayran.graph.namespaces import GlobalReleaseManager, target_stream

STAMP = "2026-08-12T12:00:00Z"
RUN_ID = "run_01K00000000000000000000001"
TARGET_ID = "tgt_01K00000000000000000000001"
STREAM_ID = "str_01K00000000000000000000001"
HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
HASH_C = "sha256:" + "c" * 64


def stream_identity() -> dict[str, Any]:
    return target_stream(
        RUN_ID,
        {
            "target_id": TARGET_ID,
            "source_tree_hash": HASH_A,
            "scope_id": "scp_01K00000000000000000000001",
            "commit": "1" * 40,
        },
        HASH_B,
        STREAM_ID,
    )


def command(ordinal: int) -> AppendCommand:
    suffix = f"01K{ordinal:023d}"
    node_id = f"nod_{suffix}"
    value = {
        "schema_version": "1.0.0",
        "node_id": node_id,
        "created_at": STAMP,
        "run_id": RUN_ID,
        "namespace": "target",
        "node_type": "Contract",
        "revision": 1,
        "status": "active",
        "properties": [
            {"name": "canonical_key", "value_type": "string", "value": f"crash:{ordinal}"}
        ],
        "trust_class": "deterministic_tool",
        "confidence": 1.0,
        "evidence_grade": "lead",
        "evidence_refs": [],
        "source_locator": f"crash/C{ordinal}.sol:1",
        "valid_from_event": "evt_01K00000000000000000000000",
        "provenance": [
            {
                "provenance_id": f"prv_{suffix}",
                "source_uri": "urn:ayran:test:crash-worker",
                "source_version": "1.0.0",
                "raw_hash": HASH_C,
                "retrieved_at": STAMP,
                "license_or_terms": "generated-test-fixture",
                "transformation_lineage": [],
            }
        ],
    }
    return AppendCommand(
        idempotency_key=f"crash:append:{ordinal}",
        items=(AppendItem("graph-node@1.0.0", "node.created", value),),
        expected_revisions={node_id: 0},
        actor={"kind": "service", "id": "test.crash-worker", "version": "1.0.0"},
        config_hash=HASH_A,
        source_version="crash-worker@1.0.0",
        operation_id=f"op_{suffix}",
        created_at=STAMP,
    )


def gate(root: Path, expected: str | None) -> Callable[[str], None]:
    def hook(point: str) -> None:
        if point != expected:
            return
        ready = root / "fault.ready"
        ready.write_text(point, encoding="utf-8")
        with ready.open("r+b") as handle:
            handle.flush()
        while True:
            time.sleep(60)

    return hook


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["append", "verify", "rebuild", "checkpoint", "global"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--fault")
    parser.add_argument("--ordinal", type=int, default=1)
    parser.add_argument("--max-segment-events", type=int, default=100_000)
    arguments = parser.parse_args()
    hook = gate(arguments.root, arguments.fault)

    if arguments.action == "global":
        manager = GlobalReleaseManager(arguments.root, fault_hook=hook)
        staging = manager.create_staging("rel_01K00000000000000000000001")
        (staging / "release.json").write_text('{"verified":true}\n', encoding="utf-8")
        result = manager.publish(staging, staging.name, HASH_A, lambda _: True)
    else:
        with GraphStore(
            arguments.root,
            stream_identity(),
            max_segment_events=arguments.max_segment_events,
            fault_hook=hook,
            fault_split_write=arguments.fault == "during_partial_write",
        ) as store:
            if arguments.action == "append":
                result = store.append(command(arguments.ordinal))
            elif arguments.action == "verify":
                result = store.verify()
            elif arguments.action == "rebuild":
                result = store.rebuild()
            else:
                result = store.checkpoint(target_hash=HASH_B, config_hash=HASH_A)
    json.dump(result, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
