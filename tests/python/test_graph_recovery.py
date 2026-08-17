from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from ayran.graph import AppendCommand, AppendItem, GraphStore
from ayran.graph.canonical import canonical_line, object_hash, sha256_bytes
from ayran.graph.errors import JOURNAL_CORRUPT, LEASE_HELD, GraphError
from ayran.graph.ids import new_id
from ayran.graph.namespaces import target_stream

TIMESTAMP = "2026-08-12T12:00:00Z"


def digest(character: str) -> str:
    return "sha256:" + character * 64


def make_stream() -> dict[str, Any]:
    return target_stream(
        new_id("run"),
        {
            "target_id": new_id("tgt"),
            "source_tree_hash": digest("a"),
            "scope_id": new_id("scp"),
            "commit": None,
        },
        digest("b"),
    )


def make_node(stream: dict[str, Any], *, node_id: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "node_id": node_id or new_id("nod"),
        "created_at": TIMESTAMP,
        "run_id": stream["run_id"],
        "namespace": "target",
        "node_type": "Contract",
        "revision": 1,
        "status": "active",
        "properties": [],
        "trust_class": "deterministic_tool",
        "confidence": 1.0,
        "evidence_grade": "lead",
        "evidence_refs": [],
        "source_locator": "src/Fixture.sol:1",
        "valid_from_event": new_id("evt"),
        "provenance": [
            {
                "provenance_id": new_id("prv"),
                "source_uri": "https://fixtures.ayran.dev/m1",
                "source_version": "fixture-v1",
                "raw_hash": digest("c"),
                "retrieved_at": TIMESTAMP,
                "license_or_terms": "private-test-fixture",
                "transformation_lineage": [],
            }
        ],
    }


def make_command(stream: dict[str, Any], key: str, *, node_id: str | None = None) -> AppendCommand:
    value = make_node(stream, node_id=node_id)
    return AppendCommand(
        idempotency_key=key,
        items=(
            AppendItem(
                contract_id="graph-node@1.0.0",
                event_type="node.created",
                value=value,
            ),
        ),
        expected_revisions={value["node_id"]: 0},
        actor={"kind": "service", "id": "test.recovery", "version": "1.0.0"},
        config_hash=digest("d"),
        source_version="test@1",
        operation_id=new_id("op"),
        created_at=TIMESTAMP,
    )


def open_store(
    root: Path,
    stream: dict[str, Any],
    *,
    fault_hook: Callable[[str], None] | None = None,
    max_segment_events: int = 100_000,
) -> GraphStore:
    return GraphStore(
        root,
        stream,
        allow_unsafe_filesystem=True,
        fault_hook=fault_hook,
        max_segment_events=max_segment_events,
    )


def append_one(root: Path, stream: dict[str, Any], key: str = "recovery:one") -> AppendCommand:
    command = make_command(stream, key)
    with open_store(root, stream) as store:
        store.append(command)
    return command


def journal_path(root: Path) -> Path:
    return root / "events" / "000001.jsonl"


def replace_first_line(path: Path, replacement: bytes, *, newline: bytes = b"\n") -> None:
    _, separator, remainder = path.read_bytes().partition(b"\n")
    assert separator == b"\n"
    path.write_bytes(replacement + newline + remainder)


def assert_corrupt(root: Path, stream: dict[str, Any]) -> None:
    with pytest.raises(GraphError) as error:
        open_store(root, stream)
    assert error.value.code == JOURNAL_CORRUPT
    diagnostics = list((root / "diagnostics").glob("*.failure.json"))
    assert diagnostics
    receipt = json.loads(diagnostics[-1].read_text(encoding="utf-8"))
    assert receipt["error"]["code"] == JOURNAL_CORRUPT


@pytest.mark.parametrize("mutation", ["duplicate_key", "crlf", "noncanonical"])
def test_journal_rejects_noncanonical_or_ambiguous_frames(
    tmp_path: Path, mutation: str
) -> None:
    stream = make_stream()
    append_one(tmp_path, stream)
    path = journal_path(tmp_path)
    first, separator, _ = path.read_bytes().partition(b"\n")
    assert separator == b"\n"

    if mutation == "duplicate_key":
        replace_first_line(
            path,
            b'{"schema_version":"1.0.0","schema_version":"1.0.0"}',
        )
    elif mutation == "crlf":
        replace_first_line(path, first, newline=b"\r\n")
    else:
        noncanonical = json.dumps(json.loads(first), separators=(", ", ": ")).encode("utf-8")
        replace_first_line(path, noncanonical)

    assert_corrupt(tmp_path, stream)


def test_incomplete_suffix_is_preserved_for_diagnostics_and_recovered(tmp_path: Path) -> None:
    stream = make_stream()
    append_one(tmp_path, stream)
    path = journal_path(tmp_path)
    committed = path.read_bytes()
    suffix = b'{"truncated":'
    path.write_bytes(committed + suffix)

    with open_store(tmp_path, stream) as recovered:
        assert recovered.projection.cursor()[0] == 1

    assert path.read_bytes() == committed
    suffixes = list((tmp_path / "diagnostics").glob("*.suffix.bin"))
    receipts = list((tmp_path / "diagnostics").glob("*.json"))
    assert len(suffixes) == len(receipts) == 1
    assert suffixes[0].read_bytes() == suffix
    receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert receipt["kind"] == "uncommitted-journal-suffix"
    assert receipt["content_hash"] == sha256_bytes(suffix)
    assert receipt["offset"] == len(committed)


def test_hash_chain_tamper_is_detected_even_when_event_hash_is_recomputed(tmp_path: Path) -> None:
    stream = make_stream()
    append_one(tmp_path, stream)
    path = journal_path(tmp_path)
    records = [json.loads(line) for line in path.read_bytes().splitlines()]
    event_record = next(record for record in records if record["record_type"] == "batch.event")
    event = event_record["event"]
    event["previous_event_hash"] = digest("e")
    event["integrity"]["content_hash"] = object_hash(event)
    event["event_hash"] = object_hash(event)
    path.write_bytes(b"".join(canonical_line(record) for record in records))

    assert_corrupt(tmp_path, stream)


def test_rotation_manifest_chain_and_closed_backup(tmp_path: Path) -> None:
    stream = make_stream()
    with open_store(tmp_path, stream, max_segment_events=1) as store:
        store.append(make_command(stream, "rotation:one"))
        store.append(make_command(stream, "rotation:two"))
        report = store.verify()

    manifests = sorted((tmp_path / "manifests").glob("*.manifest.json"))
    assert report["verified_segments"] == report["verified_events"] == 2
    assert len(manifests) == 2
    first = json.loads(manifests[0].read_text(encoding="utf-8"))
    second = json.loads(manifests[1].read_text(encoding="utf-8"))
    assert first["segment_name"] == "000001.jsonl"
    assert second["segment_name"] == "000002.jsonl"
    assert first["event_count"] == second["event_count"] == 1
    assert first["previous_manifest_hash"] is None
    assert second["previous_manifest_hash"] == first["integrity"]["content_hash"]


def test_retry_after_lost_ack_following_sqlite_commit_is_idempotent(tmp_path: Path) -> None:
    stream = make_stream()
    command = make_command(stream, "lost-ack:one")

    def crash_after_commit(point: str) -> None:
        if point == "after_sqlite_commit":
            raise RuntimeError("simulated acknowledgement loss")

    with (
        open_store(tmp_path, stream, fault_hook=crash_after_commit) as store,
        pytest.raises(RuntimeError, match="acknowledgement loss"),
    ):
        store.append(command)

    with open_store(tmp_path, stream) as recovered:
        acknowledgement = recovered.append(command)
        report = recovered.verify()

    assert acknowledgement["idempotent_replay"] is True
    assert report["journal_cursor"] == report["projection_cursor"] == 1
    assert report["verified_events"] == 1


def test_replay_recovers_after_crash_immediately_after_journal_fsync(tmp_path: Path) -> None:
    stream = make_stream()
    command = make_command(stream, "fsync:one")

    def crash_after_journal_fsync(point: str) -> None:
        if point == "after_journal_fsync":
            raise RuntimeError("simulated process loss after journal fsync")

    with (
        open_store(tmp_path, stream, fault_hook=crash_after_journal_fsync) as store,
        pytest.raises(RuntimeError, match="journal fsync"),
    ):
        store.append(command)

    with open_store(tmp_path, stream) as recovered:
        acknowledgement = recovered.append(command)
        report = recovered.verify()

    assert acknowledgement["idempotent_replay"] is True
    assert report["journal_cursor"] == report["projection_cursor"] == 1
    assert report["verified_batches"] == 1


def test_deleted_projection_replays_then_rebuilds_to_the_same_digest(tmp_path: Path) -> None:
    stream = make_stream()
    with open_store(tmp_path, stream) as store:
        store.append(make_command(stream, "projection:one"))
        store.append(make_command(stream, "projection:two"))
        expected_digest = store.projection.logical_digest()

    pointer = json.loads((tmp_path / "projection.current.json").read_text(encoding="utf-8"))
    projection = tmp_path / "projections" / pointer["filename"]
    for path in (projection, Path(str(projection) + "-wal"), Path(str(projection) + "-shm")):
        path.unlink(missing_ok=True)

    with open_store(tmp_path, stream) as replayed:
        assert replayed.projection.logical_digest() == expected_digest
        rebuilt = replayed.rebuild()
        assert replayed.projection.logical_digest() == expected_digest

    assert rebuilt["cursor"] == 2
    assert rebuilt["logical_digest"] == expected_digest


def test_checkpoint_can_anchor_a_rebuild_request(tmp_path: Path) -> None:
    stream = make_stream()
    with open_store(tmp_path, stream) as store:
        store.append(make_command(stream, "checkpoint:one"))
        checkpoint = store.checkpoint(target_hash=digest("f"), config_hash=digest("d"))
        checkpoint_path = tmp_path / "checkpoints" / f"{checkpoint['checkpoint_id']}.json"
        rebuilt = store.rebuild(from_checkpoint=checkpoint_path)

    assert checkpoint_path.is_file()
    assert rebuilt["from_checkpoint"] is True
    assert rebuilt["cursor"] == 1


def test_writer_lease_blocks_a_second_store(tmp_path: Path) -> None:
    stream = make_stream()
    first = open_store(tmp_path, stream)
    try:
        with pytest.raises(GraphError) as error:
            open_store(tmp_path, stream)
        assert error.value.code == LEASE_HELD
    finally:
        first.close()


def test_corrupt_projection_is_rebuilt_without_changing_the_journal(tmp_path: Path) -> None:
    stream = make_stream()
    append_one(tmp_path, stream)
    journal_before = journal_path(tmp_path).read_bytes()
    pointer = json.loads((tmp_path / "projection.current.json").read_text(encoding="utf-8"))
    projection = tmp_path / "projections" / pointer["filename"]
    for suffix in ("-wal", "-shm"):
        Path(str(projection) + suffix).unlink(missing_ok=True)
    projection.write_bytes(b"not a sqlite database")

    with open_store(tmp_path, stream) as recovered:
        report = recovered.verify()

    assert report["status"] == "ok"
    assert report["journal_cursor"] == report["projection_cursor"] == 1
    assert journal_path(tmp_path).read_bytes() == journal_before


def test_snapshot_reader_remains_consistent_during_append(tmp_path: Path) -> None:
    stream = make_stream()
    with open_store(tmp_path, stream) as store:
        store.append(make_command(stream, "snapshot:one"))
        with store.projection.snapshot() as reader:
            before = reader.execute("SELECT value FROM meta WHERE key='cursor'").fetchone()[0]
            store.append(make_command(stream, "snapshot:two"))
            during = reader.execute("SELECT value FROM meta WHERE key='cursor'").fetchone()[0]
        after = store.projection.cursor()[0]

    assert before == during == "1"
    assert after == 2


def test_busy_projection_returns_store_busy_and_replays_durable_batch(tmp_path: Path) -> None:
    stream = make_stream()
    store = open_store(tmp_path, stream)
    blocker = sqlite3.connect(store.projection.path, isolation_level=None)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        with pytest.raises(GraphError) as error:
            store.append(make_command(stream, "busy:one"))
        assert error.value.code == "STORE_BUSY"
    finally:
        blocker.rollback()
        blocker.close()
        store.close()

    with open_store(tmp_path, stream) as recovered:
        report = recovered.verify()
    assert report["journal_cursor"] == report["projection_cursor"] == 1
