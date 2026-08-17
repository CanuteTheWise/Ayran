"""M8 WSL ext4: full learning pipeline, routing rollback, optional Fizz detect."""

from __future__ import annotations

import asyncio
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
from ayran.context.queries import OntologyQueries
from ayran.graph.namespaces import TargetNamespace
from ayran.graph.recovery import GraphStore
from ayran.learning.promote import promote_candidate
from ayran.learning.rollback import rollback
from ayran.process.supervisor import ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from ayran.tools.registry import CapabilityRegistry
from ayran.tools.types import ALIAS_FIZZ, Environment
from m3_fixtures import scope_value
from m5_fixtures import RUN_ID, TARGET_IDENTITY, TARGET_KEY
from m7_fixtures import invoke, payload
from m8_fixtures import CLAIM, graph_args, ready_candidate

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
    token = b"m8-test-token"

    def handler(method: str, params: dict[str, Any], credentials: object) -> Any:
        _ = credentials
        return dispatcher.dispatch(method, params)

    server = AyranServer(sock, token=token, logger=logger, handler=handler, run_id=RUN_ID)
    dispatcher.shutdown_callback = server.stop
    server.start_background()
    time.sleep(0.05)
    return server, sock, token, store


def test_wsl_learning_pipeline_promote_rollback_and_queries(tmp_path: Path) -> None:
    server, sock, token, store = _start(tmp_path)
    learning_root = tmp_path / "learning"
    try:
        candidate = ready_candidate(store, claim=CLAIM)
        released = promote_candidate(
            candidate,
            store=store,
            learning_root=learning_root,
            holdouts=[],
        )
        client = AyranClient(sock, token_bytes=token)
        status = client.call("learning.status", learning_root=str(learning_root))
        assert isinstance(status, dict)
        queries = OntologyQueries(store=store)
        lessons = asyncio.run(queries.get_promoted_lessons())
        assert lessons
        policy = asyncio.run(queries.get_routing_policy())
        assert policy.get("policy_id") != "m8-stub"
        rolled = rollback(released.release_id, store=store, learning_root=learning_root)
        assert rolled.restored_pointer
    finally:
        server.stop()
        store.close()
    args = graph_args(tmp_path, store)
    code, output = invoke(["learning", "status", *args])
    assert code == 0, output
    body = payload(output)
    assert body["ok"] is True


def test_wsl_fizz_detect_optional() -> None:
    env = Environment(allowed_binary_roots=(), probe_http=False)
    registry = CapabilityRegistry(ROOT / "capabilities", environment=env, probe_on_load=True)
    adapter = registry.get_adapter(ALIAS_FIZZ, require_available=False)
    detected = asyncio.run(adapter.detect(env))
    assert detected.alias == ALIAS_FIZZ
    assert detected.status in {
        "available",
        "unavailable_not_found",
        "unavailable_broken",
        "unavailable_wrong_version",
    }
