from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from ayran.api.validators import ContractValidationError, validate_contract
from ayran.graph import AppendCommand, AppendItem, GraphStore
from ayran.graph.cli import main as cli_main
from ayran.graph.errors import GraphError
from ayran.graph.migrations import MIGRATIONS
from ayran.graph.namespaces import GlobalReleaseManager, target_stream

STAMP = "2026-08-12T12:00:00Z"
HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64


def stream() -> dict[str, Any]:
    return target_stream(
        "run_01K00000000000000000000002",
        {
            "target_id": "tgt_01K00000000000000000000002",
            "source_tree_hash": HASH_A,
            "scope_id": "scp_01K00000000000000000000002",
            "commit": None,
        },
        HASH_B,
        "str_01K00000000000000000000002",
    )


def command() -> AppendCommand:
    node_id = "nod_01K00000000000000000000002"
    value = {
        "schema_version": "1.0.0",
        "node_id": node_id,
        "created_at": STAMP,
        "run_id": "run_01K00000000000000000000002",
        "namespace": "target",
        "node_type": "Contract",
        "revision": 1,
        "status": "active",
        "properties": [],
        "trust_class": "deterministic_tool",
        "confidence": 1.0,
        "evidence_grade": "lead",
        "evidence_refs": [],
        "source_locator": "src/Ops.sol:1",
        "valid_from_event": "evt_01K00000000000000000000002",
        "provenance": [
            {
                "provenance_id": "prv_01K00000000000000000000002",
                "source_uri": "urn:ayran:test:operations",
                "source_version": "1.0.0",
                "raw_hash": HASH_B,
                "retrieved_at": STAMP,
                "license_or_terms": "generated-test-fixture",
                "transformation_lineage": [],
            }
        ],
    }
    return AppendCommand(
        "operations:one",
        (AppendItem("graph-node@1.0.0", "node.created", value),),
        {node_id: 0},
        {"kind": "service", "id": "test.operations", "version": "1.0.0"},
        HASH_A,
        "operations@1.0.0",
        created_at=STAMP,
    )


def test_closed_segment_backup_is_hash_verified(tmp_path: Path) -> None:
    with GraphStore(
        tmp_path, stream(), allow_unsafe_filesystem=True, max_segment_events=1
    ) as store:
        store.append(command())
        receipts = store.journal.backup_closed()
    assert len(receipts) == 1
    assert receipts[0]["segment_name"] == "000001.jsonl"
    assert (tmp_path / "backups" / "000001.jsonl").is_file()
    assert (tmp_path / "backups" / "000001.backup-receipt.json").is_file()


def test_global_release_publish_immutability_and_pointer_rollback(tmp_path: Path) -> None:
    manager = GlobalReleaseManager(tmp_path, allow_unsafe_filesystem=True)
    first = manager.create_staging("rel_01K00000000000000000000001")
    (first / "release.json").write_text('{"name":"first"}\n', encoding="utf-8")
    manager.publish(first, first.name, HASH_A, lambda _: True)
    second = manager.create_staging("rel_01K00000000000000000000002")
    (second / "release.json").write_text('{"name":"second"}\n', encoding="utf-8")
    manager.publish(second, second.name, HASH_B, lambda _: True)
    rolled_back = manager.rollback("rel_01K00000000000000000000001")
    assert rolled_back["previous_release_id"] == "rel_01K00000000000000000000002"
    current = manager.current_release()
    assert current is not None
    assert current["release_id"] == "rel_01K00000000000000000000001"
    duplicate = manager.create_staging("rel_01K00000000000000000000001")
    with pytest.raises(GraphError):
        manager.publish(duplicate, duplicate.name, HASH_A, lambda _: True)


def test_forward_only_migration_precheck_transform_and_validation() -> None:
    migration = MIGRATIONS[0]
    migration.precheck(0)
    event = {"journal_format_version": 1, "event_id": "evt_01K00000000000000000000001"}
    assert migration.apply_event_transform(event) is event
    migration.validate((True, []))
    with pytest.raises(ValueError):
        migration.precheck(2)
    with pytest.raises(ValueError):
        migration.apply_event_transform({"journal_format_version": 2})
    with pytest.raises(ValueError):
        migration.validate((False, ["bad projection"]))


def test_unsafe_jcs_integer_is_a_clean_contract_rejection() -> None:
    value = command().items[0].value
    value["properties"] = [
        {"name": "too_large", "value_type": "integer", "value": 9_007_199_254_740_992}
    ]
    value["integrity"] = {
        "algorithm": "sha256",
        "canonicalization": "rfc8785",
        "content_hash": HASH_A,
        "excluded_fields": ["integrity.content_hash"],
    }
    with pytest.raises(ContractValidationError, match="RFC 8785 canonicalizable"):
        validate_contract("graph-node", value)


def test_graph_cli_verify_emits_canonical_result(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    identity = stream()
    stream_path = tmp_path / "stream.json"
    stream_path.write_text(json.dumps(identity), encoding="utf-8")
    graph_root = tmp_path / "graph"
    with GraphStore(graph_root, identity, allow_unsafe_filesystem=True) as store:
        store.append(command())
    assert (
        cli_main(
            [
                "graph",
                "verify",
                "--root",
                str(graph_root),
                "--stream",
                str(stream_path),
                "--allow-unsafe-filesystem",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["result"]["status"] == "ok"
