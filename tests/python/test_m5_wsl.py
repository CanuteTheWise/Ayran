"""M5 WSL ext4: sidecar compile, maps, router session, CLI, blind/aware."""

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
from ayran.process.supervisor import ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from m3_fixtures import scope_value
from m5_fixtures import CLUSTER, RUN_ID, SLITHER_VAULT, TARGET_IDENTITY, TARGET_KEY, VAULT_SOURCE

pytestmark = pytest.mark.wsl_ext4

ROOT = Path(__file__).resolve().parents[2]


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
    token = b"m5-test-token"

    def handler(method: str, params: dict[str, Any], credentials: object) -> Any:
        _ = credentials
        return dispatcher.dispatch(method, params)

    server = AyranServer(sock, token=token, logger=logger, handler=handler, run_id=RUN_ID)
    dispatcher.shutdown_callback = server.stop
    server.start_background()
    time.sleep(0.05)
    return server, sock, token, store


def test_wsl_compile_inject_roundtrip(tmp_path: Path) -> None:
    server, sock, token, store = _start(tmp_path)
    try:
        client = AyranClient(sock, token_bytes=token)
        built = client.call(
            "maps.build",
            map_type="attack_surface",
            cluster_id=CLUSTER,
            source_text=VAULT_SOURCE,
            slither_json=SLITHER_VAULT,
        )
        assert built["node_count"] >= 1
        pack = client.call("context.compile", token_budget=4000, cluster_id=CLUSTER)
        assert pack["reconstruction_ok"] is True
        assert pack["pack"]["sections"]
        assert "injection_text" in pack
        assert "checksum:" in pack["injection_text"]
        again = client.call("context.compile", token_budget=4000, cluster_id=CLUSTER)
        assert again["content_hash"] == pack["content_hash"]
    finally:
        server.stop()
        store.close()


def test_wsl_router_session_and_blind_aware(tmp_path: Path) -> None:
    server, sock, token, store = _start(tmp_path)
    try:
        client = AyranClient(sock, token_bytes=token)
        client.call(
            "maps.build",
            map_type="attack_surface",
            cluster_id=CLUSTER,
            source_text=VAULT_SOURCE,
        )
        status = client.call("router.status", cluster_id=CLUSTER)
        assert "model_native" in status["budget"]["spent"]
        for name, spent in status["budget"]["spent"].items():
            assert spent <= status["budget"]["ceilings"][name]
        step = client.call("router.step", cluster_id=CLUSTER, persist=True)
        assert step["checksum"].startswith("sha256:")
        origins = step["origins"]
        assert origins.get("model_native") == "model_novel"
        replay = client.call("router.step", cluster_id=CLUSTER, persist=False)
        _ = replay
        history = client.call("router.history", limit=10)
        assert history["count"] >= 1
        coverage = client.call("coverage.summary", cluster_id=CLUSTER)
        assert coverage["schema_version"] == "1.0.0"
        surface = client.call("maps.get", map_type="attack_surface", cluster_id=CLUSTER)
        assert surface["present"] is True
        blind = client.call(
            "context.compile",
            token_budget=4000,
            cluster_id=CLUSTER,
            knowledge_policy="knowledge_blind",
        )
        labels = {section["classification"] for section in blind["pack"]["sections"]}
        assert "HISTORICAL_REFERENCE" not in labels
        metrics = step.get("anchoring_metrics") or {}
        _ = metrics
    finally:
        server.stop()
        store.close()


def test_wsl_cli_router_status_and_maps(tmp_path: Path) -> None:
    from ayran.cli import main as cli_main

    server, sock, token, store = _start(tmp_path)
    root = store.root
    stream = tmp_path / "stream.json"
    stream.write_text(json.dumps(store.stream), encoding="utf-8")
    server.stop()
    store.close()
    import io
    from contextlib import redirect_stdout

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli_main(
            [
                "maps",
                "attack_surface",
                "--graph-root",
                str(root),
                "--stream",
                str(stream),
                "--allow-unsafe-filesystem",
                "--source",
                str(ROOT / "fixtures" / "cognitive" / "VulnerableVault.sol"),
            ]
        )
    assert code == 0, buffer.getvalue()
    assert "attack_surface" in buffer.getvalue()
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli_main(
            [
                "router",
                "status",
                "--graph-root",
                str(root),
                "--stream",
                str(stream),
                "--allow-unsafe-filesystem",
            ]
        )
    assert code == 0
    assert "model_native" in buffer.getvalue()
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli_main(
            [
                "coverage",
                "summary",
                "--graph-root",
                str(root),
                "--stream",
                str(stream),
                "--allow-unsafe-filesystem",
            ]
        )
    assert code == 0
    _ = sock
    _ = token
