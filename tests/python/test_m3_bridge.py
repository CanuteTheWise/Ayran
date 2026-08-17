"""M3 Python bridge: context packs, policy routing, lifecycle records."""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from ayran.artifacts.store import ArtifactStore
from ayran.bridge.context_pack import RECONSTRUCTION_TITLES, compile_context_pack
from ayran.bridge.handler import build_dispatcher
from ayran.bridge.kernel import detect_kernel
from ayran.config.loader import load_config
from ayran.graph.namespaces import TargetNamespace
from ayran.graph.recovery import GraphStore
from ayran.process.supervisor import ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from m3_fixtures import RUN_ID, TARGET_IDENTITY, TARGET_KEY, scope_value


@pytest.fixture
def dispatcher(tmp_path: Path) -> Iterator[Any]:
    namespace = TargetNamespace(
        tmp_path / "graph",
        RUN_ID,
        TARGET_IDENTITY,
        TARGET_KEY,
        allow_unsafe_filesystem=True,
    )
    store = GraphStore(namespace.root, namespace.stream, allow_unsafe_filesystem=True)
    run_root = tmp_path / "run"
    run_root.mkdir()
    (run_root / "scope.json").write_text(json.dumps(scope_value()), encoding="utf-8")
    logger = StructuredLogger(run_root / "runtime.jsonl", run_id=RUN_ID, component="test")
    artifacts = ArtifactStore(run_root / "artifacts", allow_unsafe_filesystem=True)
    supervisor = ProcessSupervisor(
        run_root / "processes", run_id=RUN_ID, logger=logger, artifact_store=artifacts
    )
    config = load_config(env={})
    built = build_dispatcher(
        run_id=RUN_ID,
        config=config,
        store=store,
        logger=logger,
        artifact_store=artifacts,
        process_supervisor=supervisor,
        receipt={"schema_version": "1.0.0", "run_id": RUN_ID, "graph_cursor": 0},
        state_root=tmp_path,
        run_root=run_root,
    )
    try:
        yield built
    finally:
        store.close()


def test_context_pack_is_bounded_and_reconstructable(dispatcher: Any) -> None:
    result = dispatcher.context_pack({"token_budget": 4000})
    pack = result["pack"]
    titles = {section["title"] for section in pack["sections"]}
    assert set(RECONSTRUCTION_TITLES).issubset(titles)
    assert result["reconstruction_ok"] is True
    assert pack["token_estimate"] <= 4000
    assert pack["integrity"]["content_hash"].startswith("sha256:")


def test_compile_context_pack_direct(tmp_path: Path) -> None:
    namespace = TargetNamespace(
        tmp_path,
        RUN_ID,
        TARGET_IDENTITY,
        TARGET_KEY,
        allow_unsafe_filesystem=True,
    )
    store = GraphStore(namespace.root, namespace.stream, allow_unsafe_filesystem=True)
    try:
        pack = compile_context_pack(store, run_id="not-a-run-id", token_budget=512)
        assert pack["run_id"] == RUN_ID
        assert {section["title"] for section in pack["sections"]} >= set(RECONSTRUCTION_TITLES)
    finally:
        store.close()


def test_policy_denies_out_of_scope_read(dispatcher: Any) -> None:
    denied = dispatcher.authorize(
        {"tool_name": "read", "arguments": {"path": "secrets/key.sol"}}
    )
    assert denied["permitted"] is False
    allowed = dispatcher.authorize(
        {"tool_name": "read", "arguments": {"path": "target/src/Vault.sol"}}
    )
    assert allowed["permitted"] is True
    passthrough = dispatcher.authorize({"tool_name": "websearch", "arguments": {"query": "x"}})
    assert passthrough["permitted"] is True
    assert passthrough["authority"] == "pass_through"


def test_lifecycle_and_child_records(dispatcher: Any) -> None:
    compact = dispatcher.lifecycle_record(
        {"event_type": "session_compact", "payload": {"summary_hash": "sha256:" + "ab" * 32}}
    )
    assert compact["node_type"] == "CompactionEvent"
    child = dispatcher.child_register(
        {"handle": {"rlm_child_id": "child-1", "name": "bug-hunter"}}
    )
    assert child["registered"] is True
    done = dispatcher.child_complete(
        {"handle": {"rlm_child_id": "child-1"}, "result": {"ok": True}}
    )
    assert done["completed"] is True
    checkpoint = dispatcher.checkpoint({})
    assert checkpoint["checkpoint_id"]


def test_kernel_detect_never_installs() -> None:
    facts = detect_kernel()
    assert "managed" in facts
    assert facts["schema_version"] == "1.0.0"


def test_unknown_rpc_is_lookup_error(dispatcher: Any) -> None:
    with pytest.raises(LookupError):
        dispatcher.dispatch("not.a.method", {})


def test_status_and_doctor_shapes(dispatcher: Any) -> None:
    status = dispatcher.status()
    assert status["sidecar"] == "reachable"
    assert status["run_id"] == RUN_ID
    doctor = dispatcher.doctor()
    assert doctor["sidecar_connectivity"] == "ok"
    assert "journal_integrity" in doctor


def test_scope_load_rebinds_policy(dispatcher: Any, tmp_path: Path) -> None:
    path = tmp_path / "rebind.json"
    path.write_text(json.dumps(scope_value()), encoding="utf-8")
    result = dispatcher.scope_load({"manifest": str(path)})
    assert result["policy_loaded"] is True
    assert result["run_id"] == RUN_ID
    assert dispatcher.scope is not None
    assert dispatcher.scope.run_id == RUN_ID
