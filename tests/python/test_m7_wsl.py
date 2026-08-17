"""M7 WSL ext4: full curated ingest, deterministic release, ontology RPC, CLI."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from ayran.api.client import AyranClient
from ayran.api.server import AyranServer
from ayran.artifacts.store import ArtifactStore
from ayran.bridge.handler import build_dispatcher
from ayran.config.loader import load_config
from ayran.graph.namespaces import TargetNamespace
from ayran.graph.recovery import GraphStore
from ayran.knowledge.corpus import build_release, query_corpus
from ayran.knowledge.service import ingest_runtime_sources
from ayran.process.supervisor import ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from m3_fixtures import scope_value
from m5_fixtures import RUN_ID, TARGET_IDENTITY, TARGET_KEY
from m7_fixtures import copy_knowledge, invoke, payload

pytestmark = pytest.mark.wsl_ext4


def _start(tmp_path: Path) -> tuple[AyranServer, Path, bytes, GraphStore]:
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
    dispatcher = build_dispatcher(
        run_id=RUN_ID,
        config=load_config(env={}),
        store=store,
        logger=logger,
        artifact_store=artifacts,
        process_supervisor=supervisor,
        receipt={"schema_version": "1.0.0", "run_id": RUN_ID, "graph_cursor": 0},
        state_root=tmp_path,
        run_root=run_root,
    )
    sock = tmp_path / "ayrand.sock"
    token = b"m7-test-token"

    def handler(method: str, params: dict[str, Any], credentials: object) -> Any:
        _ = credentials
        return dispatcher.dispatch(method, params)

    server = AyranServer(sock, token=token, logger=logger, handler=handler, run_id=RUN_ID)
    dispatcher.shutdown_callback = server.stop
    server.start_background()
    time.sleep(0.05)
    return server, sock, token, store


def test_wsl_full_ingest_and_deterministic_release(tmp_path: Path) -> None:
    first = copy_knowledge(tmp_path, "a")
    second = copy_knowledge(tmp_path, "b")
    ingest_runtime_sources(first)
    ingest_runtime_sources(second)
    a = build_release(first, version="v0.1.0")
    b = build_release(second, version="v0.1.0")
    assert a["content_hash"] == b["content_hash"]
    mechanisms = query_corpus(first, record_type="mechanism", filters={"language": "solidity"})
    assert mechanisms
    traps = query_corpus(first, record_type="false_positive_trap")
    assert traps
    assert any(item.get("hard_negative") for item in traps)


def test_wsl_sidecar_knowledge_rpc_and_ontology(tmp_path: Path) -> None:
    root = copy_knowledge(tmp_path)
    server, sock, token, store = _start(tmp_path)
    try:
        client = AyranClient(sock, token_bytes=token)
        listed = client.call("knowledge.list_sources", knowledge_root=str(root))
        assert listed["count"] >= 4
        for source_id in ("zeroskills", "solodit", "0xsimao", "krait"):
            ingested = client.call(
                "knowledge.ingest", source_id=source_id, knowledge_root=str(root)
            )
            assert ingested["accepted"] >= 1
        released = client.call("knowledge.release", version="v0.1.0", knowledge_root=str(root))
        assert released["content_hash"].startswith("sha256:")
        status = client.call("knowledge.status", knowledge_root=str(root))
        assert status["record_counts"]
        queried = client.call(
            "knowledge.query",
            type="mechanism",
            filter={"language": "solidity"},
            knowledge_root=str(root),
        )
        assert queried["count"] >= 1
        mechanisms = client.call(
            "ontology.query", name="search_mechanisms", params={"query_text": "reentrancy", "budget": 5}
        )
        assert mechanisms
        blind = client.call(
            "context.compile",
            token_budget=4000,
            knowledge_policy="knowledge_blind",
        )
        aware = client.call(
            "context.compile",
            token_budget=4000,
            knowledge_policy="graph_aware",
        )
        blind_labels = {section["classification"] for section in blind["pack"]["sections"]}
        aware_labels = {section["classification"] for section in aware["pack"]["sections"]}
        assert "HISTORICAL_REFERENCE" not in blind_labels
        assert "HISTORICAL_REFERENCE" in aware_labels
        tomb = client.call(
            "knowledge.tombstone",
            source_id="solodit",
            reason="revoked",
            version="v0.1.1",
            knowledge_root=str(root),
        )
        assert tomb["tombstone"]["source_id"] == "solodit"
        after = client.call(
            "knowledge.query", type="incident", filter={}, knowledge_root=str(root)
        )
        assert all(item["source_ref"]["source_id"] != "solodit" for item in after["records"])
    finally:
        server.stop()
        store.close()


def test_wsl_cli_knowledge_commands(tmp_path: Path) -> None:
    root = copy_knowledge(tmp_path)
    args = ["--knowledge-root", str(root)]
    code, output = invoke(["knowledge", "list-sources", *args])
    assert code == 0, output
    assert "zeroskills" in output
    for source_id in ("zeroskills", "solodit", "0xsimao", "krait"):
        code, output = invoke(["knowledge", "ingest", source_id, *args])
        assert code == 0, output
    code, output = invoke(["knowledge", "release", "--version", "v0.1.0", *args])
    assert code == 0, output
    code, output = invoke(["knowledge", "status", *args])
    assert code == 0, output
    status = payload(output)["result"]
    assert status["record_counts"]
    code, output = invoke(
        ["knowledge", "query", "--type", "mechanism", "--filter", '{"language": "solidity"}', *args]
    )
    assert code == 0, output
    assert payload(output)["result"]["count"] >= 1
