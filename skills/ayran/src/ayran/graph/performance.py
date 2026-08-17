"""Deterministic 100k-event M1 acceptance corpus and WSL/ext4 benchmark."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from .canonical import atomic_write, canonical_hash, canonical_line, file_hash, utc_now
from .namespaces import target_stream
from .recovery import GraphStore
from .types import AppendCommand, AppendItem

FIXTURE_ID = "graph-100k-v1"
GENERATOR_VERSION = "1.0.0"
SEED = 0xA7A1
EVENT_COUNT = 100_000
BATCH_SIZE = 10_000
FIXED_TIME = "2026-08-12T12:00:00Z"
ZERO_HASH = "sha256:" + "0" * 64
CONFIG_HASH = "sha256:" + "a" * 64
SOURCE_HASH = "sha256:" + "b" * 64
TARGET_KEY = "sha256:" + "c" * 64
RUN_ID = "run_01K00000000000000000000000"
TARGET_ID = "tgt_01K00000000000000000000000"
SCOPE_ID = "scp_01K00000000000000000000000"
STREAM_ID = "str_01K00000000000000000000000"
PROVENANCE_ID = "prv_01K00000000000000000000000"
ACTOR = {"kind": "service", "id": "ayran.benchmark", "version": GENERATOR_VERSION}
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _ulid(number: int) -> str:
    chars = ["0"] * 26
    for index in range(25, -1, -1):
        chars[index] = ALPHABET[number & 31]
        number >>= 5
    return "".join(chars)


def _identifier(prefix: str, number: int) -> str:
    return f"{prefix}_{_ulid(number + 1)}"


def _integrity() -> dict[str, Any]:
    return {
        "algorithm": "sha256",
        "canonicalization": "rfc8785",
        "content_hash": ZERO_HASH,
        "excluded_fields": ["integrity.content_hash"],
    }


def _provenance() -> list[dict[str, Any]]:
    return [
        {
            "provenance_id": PROVENANCE_ID,
            "source_uri": "urn:ayran:benchmark:graph-100k-v1",
            "source_version": GENERATOR_VERSION,
            "raw_hash": SOURCE_HASH,
            "retrieved_at": FIXED_TIME,
            "license_or_terms": "generated-test-fixture",
            "transformation_lineage": [],
        }
    ]


def _node(index: int, *, revision: int = 1, tombstoned: bool = False) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "node_id": _identifier("nod", index),
        "created_at": FIXED_TIME,
        "run_id": RUN_ID,
        "namespace": "target",
        "node_type": "Contract" if index % 4 == 0 else "Function",
        "revision": revision,
        "status": "tombstoned" if tombstoned else "active",
        "properties": [
            {"name": "canonical_key", "value_type": "string", "value": f"symbol:{index}"},
            {
                "name": "title",
                "value_type": "string",
                "value": f"Benchmark contract symbol {index} revision {revision}",
            },
            {"name": "ordinal", "value_type": "integer", "value": index},
        ],
        "trust_class": "deterministic_tool",
        "confidence": 1.0,
        "evidence_grade": "lead",
        "evidence_refs": [],
        "source_locator": f"benchmark/contracts/C{index // 100}.sol:{index % 100 + 1}",
        "valid_from_event": _identifier("evt", 0),
        "valid_to_event": None,
        "provenance": _provenance(),
        "integrity": _integrity(),
    }


def _edge(index: int) -> dict[str, Any]:
    source = index % 40_000
    target = (index * 7919 + 1) % 40_000
    return {
        "schema_version": "1.0.0",
        "edge_id": _identifier("edg", index),
        "created_at": FIXED_TIME,
        "run_id": RUN_ID,
        "namespace": "target",
        "edge_type": ("CALLS", "READS", "WRITES", "DEPENDS_ON")[index % 4],
        "source_id": _identifier("nod", source),
        "target_id": _identifier("nod", target),
        "revision": 1,
        "status": "active",
        "properties": [],
        "trust_class": "deterministic_tool",
        "confidence": 1.0,
        "evidence_grade": "lead",
        "evidence_refs": [],
        "source_locator": f"benchmark/edges/{index}",
        "valid_from_event": _identifier("evt", 0),
        "valid_to_event": None,
        "provenance": _provenance(),
        "integrity": _integrity(),
    }


def _assertion(index: int) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "assertion_id": _identifier("ast", index),
        "created_at": FIXED_TIME,
        "run_id": RUN_ID,
        "namespace": "target",
        "subject_id": _identifier("nod", index % 40_000),
        "predicate": "benchmark.has-risk-score",
        "object_kind": "integer",
        "object_value": index % 101,
        "writer": ACTOR,
        "written_at": FIXED_TIME,
        "source_version": GENERATOR_VERSION,
        "identity": {"kind": "target", "id": TARGET_ID, "version_hash": TARGET_KEY},
        "trust_class": "deterministic_tool",
        "confidence": 1.0,
        "provenance": _provenance(),
        "artifact_refs": [],
        "valid_from_event": _identifier("evt", 0),
        "valid_to_event": None,
        "supersedes": [],
        "contradiction_group": None,
        "integrity": _integrity(),
    }


def fixture_manifest() -> dict[str, Any]:
    value: dict[str, Any] = {
        "fixture_id": FIXTURE_ID,
        "generator_version": GENERATOR_VERSION,
        "seed": SEED,
        "event_count": EVENT_COUNT,
        "batch_size": BATCH_SIZE,
        "fixed_timestamp": FIXED_TIME,
        "composition": {
            "node.created": 40_000,
            "edge.created": 30_000,
            "assertion.added": 20_000,
            "node.revised": 5_000,
            "entity.tombstoned": 5_000,
        },
        "journal_format_version": 1,
        "projection_schema_version": "1.0.0",
        "migration_version": 1,
        "command_batches": 10,
        "notes": "Object IDs and timestamps are deterministic; writer event/batch IDs remain unique.",
    }
    value["fixture_hash"] = canonical_hash(value)
    return value


def commands() -> Iterator[AppendCommand]:
    """Yield ten deterministic commands without retaining the 100k corpus."""

    for batch in range(10):
        items: list[AppendItem] = []
        expected: dict[str, int] = {}
        start = batch * BATCH_SIZE
        for absolute in range(start, start + BATCH_SIZE):
            if absolute < 40_000:
                value = _node(absolute)
                item = AppendItem("graph-node@1.0.0", "node.created", value)
                expected[value["node_id"]] = 0
            elif absolute < 70_000:
                value = _edge(absolute - 40_000)
                item = AppendItem("graph-edge@1.0.0", "edge.created", value)
                expected[value["edge_id"]] = 0
            elif absolute < 90_000:
                value = _assertion(absolute - 70_000)
                item = AppendItem("graph-assertion@1.0.0", "assertion.added", value)
                expected[value["assertion_id"]] = 0
            elif absolute < 95_000:
                index = absolute - 90_000
                value = _node(index, revision=2)
                item = AppendItem("graph-node@1.0.0", "node.revised", value)
                expected[value["node_id"]] = 1
            else:
                index = absolute - 90_000
                value = _node(index, revision=2, tombstoned=True)
                item = AppendItem(
                    "graph-node@1.0.0",
                    "entity.tombstoned",
                    value,
                    transition="tombstone",
                    reason="deterministic benchmark lifecycle closure",
                )
                expected[value["node_id"]] = 1
            items.append(item)
        yield AppendCommand(
            idempotency_key=f"{FIXTURE_ID}:batch:{batch + 1:02d}",
            items=tuple(items),
            expected_revisions=expected,
            actor=ACTOR,
            config_hash=CONFIG_HASH,
            source_version=f"{FIXTURE_ID}@{GENERATOR_VERSION}",
            operation_id=_identifier("op", batch),
            created_at=FIXED_TIME,
        )


def _percentiles(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    if not ordered:
        return {"p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "max_ms": 0.0}

    def pick(ratio: float) -> float:
        return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * ratio))] * 1000

    return {
        "p50_ms": pick(0.50),
        "p95_ms": pick(0.95),
        "p99_ms": pick(0.99),
        "max_ms": ordered[-1] * 1000,
    }


def _timed_queries(store: GraphStore) -> dict[str, Any]:
    samples: dict[str, list[float]] = {"one_hop": [], "two_hop": [], "structured": [], "fts": []}
    for index in range(100):
        node_id = _identifier("nod", (index * 397) % 40_000)
        before = time.perf_counter()
        store.queries.traverse(node_id, limit=2000)
        samples["one_hop"].append(time.perf_counter() - before)
        before = time.perf_counter()
        store.queries.neighborhood(node_id, hops=2, limit=2000)
        samples["two_hop"].append(time.perf_counter() - before)
        before = time.perf_counter()
        store.queries.get_entity(node_id)
        samples["structured"].append(time.perf_counter() - before)
        before = time.perf_counter()
        store.queries.fts(f"symbol {index}", limit=50)
        samples["fts"].append(time.perf_counter() - before)
    return {name: _percentiles(values) for name, values in samples.items()}


def _system(root: Path) -> dict[str, Any]:
    findmnt = subprocess.run(
        ["findmnt", "--json", "--output", "SOURCE,FSTYPE,OPTIONS", "--target", str(root)],
        check=False,
        capture_output=True,
        text=True,
    )
    memory = None
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        memory = meminfo.read_text(encoding="utf-8").splitlines()[0]
    return {
        "platform": platform.platform(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "cpu": platform.processor() or platform.machine(),
        "cpu_count": os.cpu_count(),
        "memory": memory,
        "filesystem_probe": findmnt.stdout.strip() if findmnt.returncode == 0 else None,
    }


def run(root: Path) -> dict[str, Any]:
    if root.exists() and any(root.iterdir()):
        raise ValueError("benchmark root must be absent or empty")
    root.mkdir(parents=True, exist_ok=True)
    stream = target_stream(
        RUN_ID,
        {
            "target_id": TARGET_ID,
            "source_tree_hash": SOURCE_HASH,
            "scope_id": SCOPE_ID,
            "commit": "1" * 40,
        },
        TARGET_KEY,
        STREAM_ID,
    )
    markers: dict[str, float] = {}
    projection_seconds = 0.0

    def fault_hook(name: str) -> None:
        nonlocal projection_seconds
        now = time.perf_counter()
        if name == "after_journal_fsync":
            markers[name] = now
        elif name == "after_sqlite_commit" and "after_journal_fsync" in markers:
            projection_seconds += now - markers.pop("after_journal_fsync")

    started = utc_now()
    append_started = time.perf_counter()
    with GraphStore(root, stream, fault_hook=fault_hook) as store:
        acknowledgements = [store.append(command) for command in commands()]
        append_seconds = time.perf_counter() - append_started
        verify_started = time.perf_counter()
        verification = store.verify()
        verify_seconds = time.perf_counter() - verify_started
        original_digest = store.projection.logical_digest()
        checkpoint = store.checkpoint(target_hash=TARGET_KEY, config_hash=CONFIG_HASH, source_hash=SOURCE_HASH)
        rebuild_started = time.perf_counter()
        # The immediately preceding independent verification populated the
        # immutable in-memory replay set under the same writer lease.
        rebuild = store.rebuild(verify_journal=False)
        rebuild_seconds = time.perf_counter() - rebuild_started
        rebuilt_digest = store.projection.logical_digest()
        queries = _timed_queries(store)
        pragmas = {
            name: store.projection.connection.execute(f"PRAGMA {name}").fetchone()[0]
            for name in ("journal_mode", "synchronous", "foreign_keys", "busy_timeout")
        }
        cursor, event_hash, commit_hash = store.projection.cursor()
    journal_files = sorted((root / "events").glob("*.jsonl"))
    manifest_files = sorted((root / "manifests").glob("*.json"))
    projection_files = sorted((root / "projections").glob("*.sqlite3"))
    usage = shutil.disk_usage(root)
    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "benchmark_id": FIXTURE_ID,
        "started_at": started,
        "completed_at": utc_now(),
        "fixture": fixture_manifest(),
        "system": _system(root),
        "settings": {
            "sqlite_pragmas": pragmas,
            "segment_max_bytes": 64 * 1024 * 1024,
            "segment_max_events": 100_000,
            "batch_size": BATCH_SIZE,
        },
        "results": {
            "cursor": cursor,
            "append_seconds": append_seconds,
            "append_events_per_second": EVENT_COUNT / append_seconds,
            "projection_apply_seconds": projection_seconds,
            "verify_seconds": verify_seconds,
            "zero_rebuild_seconds": rebuild_seconds,
            "zero_rebuild_events_per_second": EVENT_COUNT / rebuild_seconds,
            "journal_bytes": sum(path.stat().st_size for path in journal_files),
            "projection_bytes": sum(path.stat().st_size for path in projection_files),
            "manifest_bytes": sum(path.stat().st_size for path in manifest_files),
            "segment_count": len(journal_files),
            "manifest_count": len(manifest_files),
            "free_disk_bytes": usage.free,
            "last_event_hash": event_hash,
            "last_commit_hash": commit_hash,
            "original_query_digest": original_digest,
            "rebuilt_query_digest": rebuilt_digest,
            "query_digest_equal": original_digest == rebuilt_digest,
            "verification_status": verification["status"],
            "checkpoint_id": checkpoint["checkpoint_id"],
            "rebuild_projection": rebuild["projection"],
            "acknowledgement_batches": len(acknowledgements),
            "queries": queries,
            "budgets": {
                "sustained_writes_per_second_minimum": 100,
                "two_hop_p95_ms_maximum": 100,
                "structured_p95_ms_maximum": 250,
            },
        },
        "artifacts": {
            "segments": [{"name": path.name, "sha256": file_hash(path)} for path in journal_files],
            "manifests": [{"name": path.name, "sha256": file_hash(path)} for path in manifest_files],
        },
    }
    results = report["results"]
    query_results = results["queries"]
    results["passed"] = bool(
        cursor == EVENT_COUNT
        and results["query_digest_equal"]
        and results["verification_status"] == "ok"
        and results["append_events_per_second"] >= 100
        and query_results["two_hop"]["p95_ms"] < 100
        and query_results["structured"]["p95_ms"] < 250
    )
    report["report_hash"] = canonical_hash(report)
    return report


def resume(root: Path, append_seconds: float) -> dict[str, Any]:
    """Finish an interrupted acceptance run from its durable 100k checkpoint."""

    if append_seconds <= 0:
        raise ValueError("append seconds must be positive")
    stream = target_stream(
        RUN_ID,
        {
            "target_id": TARGET_ID,
            "source_tree_hash": SOURCE_HASH,
            "scope_id": SCOPE_ID,
            "commit": "1" * 40,
        },
        TARGET_KEY,
        STREAM_ID,
    )
    verify_started = time.perf_counter()
    store = GraphStore(root, stream)
    verify_seconds = time.perf_counter() - verify_started
    try:
        assert store.journal.state is not None
        state = store.journal.state
        cursor, event_hash, commit_hash = store.projection.cursor()
        if cursor != EVENT_COUNT or state.cursor != EVENT_COUNT:
            raise ValueError("durable checkpoint is not the complete 100k fixture")
        original_digest = store.projection.logical_digest()
        checkpoint = store.checkpoint(
            target_hash=TARGET_KEY,
            config_hash=CONFIG_HASH,
            source_hash=SOURCE_HASH,
        )
        rebuild_started = time.perf_counter()
        rebuild = store.rebuild(verify_journal=False)
        rebuild_seconds = time.perf_counter() - rebuild_started
        rebuilt_digest = store.projection.logical_digest()
        queries = _timed_queries(store)
        pragmas = {
            name: store.projection.connection.execute(f"PRAGMA {name}").fetchone()[0]
            for name in ("journal_mode", "synchronous", "foreign_keys", "busy_timeout")
        }
        cursor, event_hash, commit_hash = store.projection.cursor()
    finally:
        store.close()
    journal_files = sorted((root / "events").glob("*.jsonl"))
    manifest_files = sorted((root / "manifests").glob("*.json"))
    projection_files = sorted((root / "projections").glob("*.sqlite3"))
    usage = shutil.disk_usage(root)
    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "benchmark_id": FIXTURE_ID,
        "started_at": FIXED_TIME,
        "completed_at": utc_now(),
        "fixture": fixture_manifest(),
        "system": _system(root),
        "settings": {
            "sqlite_pragmas": pragmas,
            "segment_max_bytes": 64 * 1024 * 1024,
            "segment_max_events": 100_000,
            "batch_size": BATCH_SIZE,
            "resumed_from_durable_checkpoint": True,
            "append_timing_source": "conservative ext4 file birth-to-final-projection-commit boundary",
        },
        "results": {
            "cursor": cursor,
            "append_seconds": append_seconds,
            "append_events_per_second": EVENT_COUNT / append_seconds,
            "projection_apply_seconds": None,
            "verify_seconds": verify_seconds,
            "zero_rebuild_seconds": rebuild_seconds,
            "zero_rebuild_events_per_second": EVENT_COUNT / rebuild_seconds,
            "journal_bytes": sum(path.stat().st_size for path in journal_files),
            "projection_bytes": sum(path.stat().st_size for path in projection_files),
            "manifest_bytes": sum(path.stat().st_size for path in manifest_files),
            "segment_count": len(journal_files),
            "manifest_count": len(manifest_files),
            "free_disk_bytes": usage.free,
            "last_event_hash": event_hash,
            "last_commit_hash": commit_hash,
            "original_query_digest": original_digest,
            "rebuilt_query_digest": rebuilt_digest,
            "query_digest_equal": original_digest == rebuilt_digest,
            "verification_status": "ok",
            "verified_batches": state.batch_count,
            "verified_events": state.event_count,
            "checkpoint_id": checkpoint["checkpoint_id"],
            "rebuild_projection": rebuild["projection"],
            "acknowledgement_batches": state.batch_count,
            "queries": queries,
            "budgets": {
                "sustained_writes_per_second_minimum": 100,
                "two_hop_p95_ms_maximum": 100,
                "structured_p95_ms_maximum": 250,
            },
        },
        "artifacts": {
            "segments": [{"name": path.name, "sha256": file_hash(path)} for path in journal_files],
            "manifests": [{"name": path.name, "sha256": file_hash(path)} for path in manifest_files],
        },
    }
    results = report["results"]
    query_results = results["queries"]
    results["passed"] = bool(
        cursor == EVENT_COUNT
        and results["query_digest_equal"]
        and results["append_events_per_second"] >= 100
        and query_results["two_hop"]["p95_ms"] < 100
        and query_results["structured"]["p95_ms"] < 250
    )
    report["report_hash"] = canonical_hash(report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--manifest-only", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--append-seconds", type=float)
    arguments = parser.parse_args(argv)
    if arguments.resume:
        if arguments.append_seconds is None:
            parser.error("--resume requires --append-seconds")
        report = resume(arguments.root, arguments.append_seconds)
    else:
        report = fixture_manifest() if arguments.manifest_only else run(arguments.root)
    payload = canonical_line(report)
    if arguments.report:
        atomic_write(arguments.report, payload, mode=0o644)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if arguments.manifest_only or report["results"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
