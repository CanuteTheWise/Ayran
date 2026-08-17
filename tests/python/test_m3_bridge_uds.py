"""M3 sidecar RPC over UDS. Requires Linux SO_PEERCRED (wsl_ext4)."""
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
from m3_fixtures import RUN_ID, TARGET_IDENTITY, TARGET_KEY, scope_value

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
    token = b"m3-test-token"

    def handler(method: str, params: dict[str, Any], credentials: object) -> Any:
        _ = credentials
        if method == "run.ping":
            return {"pong": True, "run_id": RUN_ID}
        return dispatcher.dispatch(method, params)

    server = AyranServer(sock, token=token, logger=logger, handler=handler, run_id=RUN_ID)
    dispatcher.shutdown_callback = server.stop
    server.start_background()
    time.sleep(0.05)
    return server, sock, token, store


def test_uds_context_pack_policy_and_commands(tmp_path: Path) -> None:
    server, sock, token, store = _start(tmp_path)
    try:
        client = AyranClient(sock, token_bytes=token)
        assert client.call("run.ping")["pong"] is True
        pack = client.call("context.pack", token_budget=4000)
        assert pack["reconstruction_ok"] is True
        denied = client.call(
            "policy.authorize",
            tool_name="read",
            arguments={"path": "secrets/key.sol"},
        )
        assert denied["permitted"] is False
        allowed = client.call(
            "policy.authorize",
            tool_name="read",
            arguments={"path": "target/src/Vault.sol"},
        )
        assert allowed["permitted"] is True
        status = client.call("run.status")
        assert status["run_id"] == RUN_ID
        doctor = client.call("run.doctor")
        assert doctor["sidecar_connectivity"] == "ok"
        kernel = client.call("kernel.detect")
        assert "managed" in kernel
    finally:
        server.stop()
        store.close()
        assert not sock.exists()
