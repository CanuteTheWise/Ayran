"""M9 resilience: disk-full, soak, malformed output, schema upgrade, orphans."""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest
from ayran.graph.canonical import write_all
from ayran.graph.errors import RESOURCE_EXHAUSTED, GraphError
from ayran.graph.migrations import MIGRATIONS
from ayran.resilience.diskfull import append_probe, raise_enospc, simulate_disk_full
from ayran.resilience.malformed import prepare_tool_output
from ayran.resilience.orphans import reap_orphans
from ayran.resilience.schema_upgrade import historical_versions, seed_projection, upgrade_and_verify
from ayran.resilience.soak import run_soak
from ayran.tools.adapters.foundry import _extract_json_object
from ayran.tools.adapters.solc import SolcAdapter
from ayran.tools.errors import PARSER_FAILED, ToolError
from ayran.tools.types import RawRun
from m9_fixtures import open_store


def test_disk_full_degrades_without_corrupting_prior_events(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        first = append_probe(store, label="before-full")
        assert first
        result = simulate_disk_full(store, write_all)
        assert result["degraded"] is True
        assert result["error"]["code"] == RESOURCE_EXHAUSTED
        again = append_probe(store, label="after-recovery")
        assert again
        assert store.projection.cursor()[0] >= 2
    finally:
        store.close()


def test_canonical_write_all_maps_enospc(monkeypatch: pytest.MonkeyPatch) -> None:
    from ayran.graph.canonical import write_all as real_write_all

    def _enospc(_fd: int, _payload: bytes) -> int:
        raise_enospc()
        return 0

    monkeypatch.setattr("ayran.graph.canonical.os.write", _enospc)
    with pytest.raises(GraphError) as raised:
        real_write_all(1, b"data")
    assert raised.value.code == RESOURCE_EXHAUSTED


def test_malformed_gzip_binary_truncated_oversized() -> None:
    gzipped = gzip.compress(b'{"ok": true}')
    prepared = prepare_tool_output(gzipped)
    assert prepared["kind"] == "gzip"
    assert '"ok"' in prepared["text"]
    binary = prepare_tool_output(b"\x00\x01\x02\xff")
    assert binary["kind"] == "binary"
    oversized = prepare_tool_output(b"x" * 100, max_bytes=10)
    assert oversized["kind"] == "oversized"
    truncated = prepare_tool_output(b"\x1f\x8b\x08\x00not-a-gzip")
    assert truncated["kind"] == "truncated_gzip"
    parsed = _extract_json_object('noise {"status":"success"}')
    assert parsed is not None


def test_solc_malformed_exit_zero_is_parse_failure() -> None:
    adapter = SolcAdapter.__new__(SolcAdapter)
    raw = RawRun(
        argv=["solc"],
        cwd=None,
        env_fingerprint="env",
        started_at="2026-08-15T00:00:00Z",
        ended_at="2026-08-15T00:00:01Z",
        exit_code=0,
        signal=None,
        stdout=b"",
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        stdout_hash="sha256:" + "0" * 64,
        stderr_hash="sha256:" + "0" * 64,
        output_file_hashes={},
        input_hashes=[],
        executable_hash=None,
        timeout=False,
        failure_type=None,
    )
    with pytest.raises(ToolError) as raised:
        adapter.parse(raw)
    assert raised.value.code == PARSER_FAILED


def test_schema_upgrade_v0001_through_v0005(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        stream = store.stream
    finally:
        store.close()
    assert historical_versions() == tuple(item.version for item in MIGRATIONS)
    for version in historical_versions():
        path = tmp_path / f"v{version}" / "projection.sqlite"
        seed_projection(path, version, stream)
        result = upgrade_and_verify(path, stream)
        assert result["ok"] is True, result


def test_simulated_24h_soak_recovers(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        result = run_soak(store)
        assert result["simulated_hours"] == 24
        assert result["acknowledged"] == 24
        assert result["data_loss"] is False
        assert result["recoverable"] is True
        assert result["events"]["sidecar_restarts"] == 3
        assert result["events"]["compactions"] == 2
        assert result["events"]["journal_corruptions"] == 1
        assert result["events"]["orphans"] == 1
        assert result["events"]["disk_full"] == 1
        assert result["events"]["tool_invocations"] == 24
    finally:
        store.close()


def test_orphan_reap_on_empty_supervisor(tmp_path: Path) -> None:
    from ayran.artifacts.store import ArtifactStore
    from ayran.process.supervisor import ProcessSupervisor
    from ayran.runtime.logs import StructuredLogger

    logger = StructuredLogger(tmp_path / "proc.log", run_id="run_01J00000000000000000000001", component="supervisor")
    supervisor = ProcessSupervisor(
        tmp_path / "proc",
        run_id="run_01J00000000000000000000001",
        logger=logger,
        artifact_store=ArtifactStore(tmp_path / "artifacts", allow_unsafe_filesystem=True),
        allowed_binary_roots=(),
    )
    result = reap_orphans(supervisor)
    assert result["reaped"] == []
    assert result["remaining"] == []
