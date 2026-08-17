"""Shared M5 identities, vault source, and GraphView builders."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ayran.context.ids import DEFAULT_CLUSTER_ID, DEFAULT_RUN_ID
from ayran.context.view import GraphView
from ayran.graph.namespaces import TargetNamespace
from ayran.graph.recovery import GraphStore

ROOT = Path(__file__).resolve().parents[2]
VAULT_SOURCE = (ROOT / "fixtures" / "cognitive" / "VulnerableVault.sol").read_text(encoding="utf-8")
SLITHER_VAULT = json.loads(
    (ROOT / "fixtures" / "cognitive" / "slither-vault.json").read_text(encoding="utf-8")
)
RUN_ID = DEFAULT_RUN_ID
TARGET_KEY = "sha256:" + "a" * 64
TARGET_IDENTITY = {
    "target_id": "tgt_01J00000000000000000000001",
    "source_tree_hash": "sha256:" + "d" * 64,
    "scope_id": "scp_01J00000000000000000000001",
    "commit": "1" * 40,
}
CREATED = "2026-08-12T12:00:00Z"
CLUSTER = DEFAULT_CLUSTER_ID


def open_store(tmp_path: Path) -> GraphStore:
    namespace = TargetNamespace(
        tmp_path / "graph",
        RUN_ID,
        TARGET_IDENTITY,
        TARGET_KEY,
        allow_unsafe_filesystem=True,
    )
    return GraphStore(namespace.root, namespace.stream, allow_unsafe_filesystem=True)


def write_stream(tmp_path: Path, store: GraphStore) -> tuple[Path, Path]:
    root = store.root
    stream_path = tmp_path / "stream.json"
    stream_path.write_text(json.dumps(store.stream), encoding="utf-8")
    return root, stream_path


def base_view(**overrides: Any) -> GraphView:
    view = GraphView(
        run_id=RUN_ID,
        target_identity=TARGET_IDENTITY,
        cluster_id=CLUSTER,
        created_at=CREATED,
        high_value_clusters=[CLUSTER],
        source_units=[
            {
                "kind": "source",
                "name": "VulnerableVault",
                "source": VAULT_SOURCE,
                "locator": "fixtures/cognitive/VulnerableVault.sol",
            }
        ],
        policy_constraints=["no broadcast", "leads stay leads"],
        value_at_risk=80,
        scope_id="scp_01J00000000000000000000001",
    )
    for key, value in overrides.items():
        setattr(view, key, value)
    return view
