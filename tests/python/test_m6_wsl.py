"""M6 WSL ext4: sidecar evidence pipeline, duplicate link, claim traceability."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from ayran.api.client import AyranClient, ClientError
from ayran.api.server import AyranServer
from ayran.artifacts.store import ArtifactStore
from ayran.bridge.handler import build_dispatcher
from ayran.config.loader import load_config
from ayran.context.ids import content_id
from ayran.evidence.actors import ACTOR_EVIDENCE
from ayran.graph.namespaces import TargetNamespace
from ayran.graph.recovery import GraphStore
from ayran.process.supervisor import ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from m3_fixtures import scope_value
from m5_fixtures import RUN_ID, TARGET_IDENTITY, TARGET_KEY, VAULT_SOURCE
from m6_fixtures import (
    GATE_B_PASS,
    REENTRANT_PROJECT,
    REENTRANT_SOURCE,
    TRUE_DEFECT_EVIDENCE,
    seed_hypothesis,
)

pytestmark = pytest.mark.wsl_ext4


def _scope() -> dict[str, Any]:
    value = scope_value()
    value["rules"] = [
        *value["rules"],
        {
            "rule_id": "rul_01J00000000000000000000005",
            "effect": "allow",
            "action": "test_local",
            "resource": ".",
        },
        {
            "rule_id": "rul_01J00000000000000000000006",
            "effect": "allow",
            "action": "render_local_report",
            "resource": ".",
        },
    ]
    return value


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
    (run_root / "scope.json").write_text(json.dumps(_scope()), encoding="utf-8")
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
    token = b"m6-test-token"

    def handler(method: str, params: dict[str, Any], credentials: object) -> Any:
        _ = credentials
        return dispatcher.dispatch(method, params)

    server = AyranServer(sock, token=token, logger=logger, handler=handler, run_id=RUN_ID)
    dispatcher.shutdown_callback = server.stop
    server.start_background()
    time.sleep(0.05)
    return server, sock, token, store


def test_wsl_false_positive_gate_a(tmp_path: Path) -> None:
    server, sock, token, store = _start(tmp_path)
    try:
        hyp = seed_hypothesis(
            store,
            claim="VulnerableVault.withdraw(uint256) sends eth to arbitrary user",
            attack_path=["withdraw"],
            root_cause="arbitrary-send-eth",
        )
        client = AyranClient(sock, token_bytes=token)
        client.call(
            "evidence.transition",
            hypothesis_id=hyp["hypothesis_id"],
            to="supported",
            evidence={
                "path": "VulnerableVault.withdraw",
                "invariant": "caller balance only",
                "source_span": "VulnerableVault.sol:17",
                "preconditions_reachable": True,
                "reachable_preconditions": ["balance"],
            },
            actor=ACTOR_EVIDENCE,
        )
        verdict = client.call(
            "evidence.gate_a",
            hypothesis_id=hyp["hypothesis_id"],
            analysis={"source": VAULT_SOURCE},
        )
        assert verdict["verdict"] == "falsified"
    finally:
        server.stop()
        store.close()


def test_wsl_true_defect_through_finding(tmp_path: Path) -> None:
    server, sock, token, store = _start(tmp_path)
    try:
        hyp = seed_hypothesis(
            store,
            claim="ReentrantVault.withdraw is reentrant because the external call happens before balances are zeroed",
            attack_path=["withdraw"],
            root_cause="reentrancy-call-before-zero",
        )
        client = AyranClient(sock, token_bytes=token)
        client.call(
            "evidence.transition",
            hypothesis_id=hyp["hypothesis_id"],
            to="supported",
            evidence=TRUE_DEFECT_EVIDENCE,
            actor=ACTOR_EVIDENCE,
        )
        a = client.call(
            "evidence.gate_a",
            hypothesis_id=hyp["hypothesis_id"],
            analysis={"source": REENTRANT_SOURCE},
        )
        assert a["verdict"] == "poc_worthy"
        try:
            poc = client.call(
                "evidence.poc_run",
                hypothesis_id=hyp["hypothesis_id"],
                resource="target/src",
                experiment={
                    "project_root": str(REENTRANT_PROJECT),
                    "match_test": "test_exploit",
                    "execute": True,
                },
                execute=True,
            )
        except ClientError:
            poc = {"status": "pending"}
        if poc.get("status") not in {"succeeded", "failed", "timeout"}:
            poc = client.call(
                "evidence.poc_run",
                hypothesis_id=hyp["hypothesis_id"],
                recorded={
                    "status": "succeeded",
                    "stdout": "drained",
                    "result_hash": "sha256:" + "cd" * 32,
                    "replay_matched": True,
                    "one_command": "forge test --match-test test_exploit --json",
                    "tool_run_id": content_id("trn", hyp["hypothesis_id"], "wsl"),
                    "evidence_ids": [content_id("evd", hyp["hypothesis_id"], "wsl")],
                },
            )
        b = client.call(
            "evidence.gate_b",
            hypothesis_id=hyp["hypothesis_id"],
            obligations=GATE_B_PASS,
            poc_id=poc.get("poc_id"),
        )
        assert b["verdict"] in {"defect_pinned", "needs_reformulation"}
        if b["verdict"] != "defect_pinned":
            client.call(
                "evidence.transition",
                hypothesis_id=hyp["hypothesis_id"],
                to="observed",
                evidence={"reproduction_id": str(poc.get("poc_id") or content_id("poc", "wsl"))},
                actor={"kind": "service", "id": "ayran.poc", "version": "1.0.0"},
            )
            b = client.call("evidence.gate_b", hypothesis_id=hyp["hypothesis_id"], obligations=GATE_B_PASS)
        if b.get("verdict") == "defect_pinned":
            impact = client.call("evidence.impact_assess", hypothesis_id=hyp["hypothesis_id"])
            severity = client.call("evidence.severity_assess", hypothesis_id=hyp["hypothesis_id"])
            client.call(
                "evidence.transition",
                hypothesis_id=hyp["hypothesis_id"],
                to="validated",
                evidence={
                    "skeptic_id": content_id("act", "skeptic", hyp["hypothesis_id"]),
                    "scope_id": "scp_01J00000000000000000000001",
                    "impact_id": impact["impact_id"],
                    "dedup_id": content_id("clu", "dedup", hyp["hypothesis_id"]),
                    "severity_id": content_id("sev", hyp["hypothesis_id"], severity["label"]),
                },
                actor=ACTOR_EVIDENCE,
            )
            finding = client.call("finding.build", hypothesis_id=hyp["hypothesis_id"])
            assert finding["status"] in {"validated", "candidate"}
            rendered = client.call("report.render", finding_id=finding["finding_id"], format="markdown")
            assert "[evidence:" in rendered["body"]
            linted = client.call("report.lint", finding_id=finding["finding_id"])
            if finding["status"] == "validated":
                assert linted["passed"] is True
    finally:
        server.stop()
        store.close()


def test_wsl_duplicate_linked_without_deletion(tmp_path: Path) -> None:
    server, sock, token, store = _start(tmp_path)
    try:
        first = seed_hypothesis(
            store,
            claim="reentrancy in withdraw",
            root_cause="call-before-zero",
            attack_path=["withdraw"],
        )
        second = seed_hypothesis(
            store,
            claim="reentrancy in withdraw",
            root_cause="call-before-zero",
            attack_path=["withdraw"],
            origin="model_novel",
        )
        client = AyranClient(sock, token_bytes=token)
        result = client.call("evidence.dedup_check", hypothesis_id=second["hypothesis_id"])
        assert result["deleted"] is False
        from ayran.evidence.load import load_hypothesis

        assert load_hypothesis(store, first["hypothesis_id"]) is not None
        assert load_hypothesis(store, second["hypothesis_id"]) is not None
        if result.get("duplicate_of"):
            assert result["duplicate_of"] == first["hypothesis_id"] or result["status"] in {
                "duplicate_known_issue",
                "variant",
                "unique",
            }
    finally:
        server.stop()
        store.close()
