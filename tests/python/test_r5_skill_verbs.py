"""R5 — §7.3 acceptance, deterministic variant: a full engagement driven
solely through the catalog verbs (spec §7, §12-R5 demo-of-done proxy).

``test_full_engagement_through_catalog_verbs`` runs ON WINDOWS: the W1 verb
client is real; only the transport is an in-process dispatcher fixture (the
UDS socket itself is wsl_ext4 territory) and the scan adapter is a scripted
fixture (real adapters need WSL toolchains). Zero JSON hand-editing, zero
routed-action prompts.

Honest scope note: the state-ladder RPCs that were NEVER part of the ten-verb
catalog (``evidence.transition`` to supported, ``evidence.poc_run`` to
observed) are dispatched directly by the scripted driver between catalog
steps; every catalog-facing step goes through the verbs.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from ayran.api.client import ClientError
from ayran.artifacts.store import ArtifactStore
from ayran.bridge.handler import build_dispatcher
from ayran.config.models import EffectiveConfig
from ayran.evidence.service import remember as _remember  # noqa: F401 (import-order cycle guard)
from ayran.process.supervisor import ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from m3_fixtures import scope_value
from m5_fixtures import RUN_ID
from m6_fixtures import open_store

CLAIM = (
    "ReentrantVault.withdraw credits msg.sender only after the external call, so an "
    "attacker fallback can re-enter withdraw before balances are zeroed and drain "
    "the pool with two withdrawals for one deposit."
)
CLUSTER = "clus_01J00000000000000000000001"
SESSION = "sess-w11"
ENROLLMENT_KEY = b"r5-w11-enrollment-key-32-bytes-aaaaaa"[:32]


class _InProcessClient:
    """Transport stand-in with the AyranClient surface (call/timeout)."""

    def __init__(self, dispatcher: Any) -> None:
        self._dispatcher = dispatcher
        self.timeout = 10.0

    def call(self, method: str, **params: Any) -> Any:
        params.pop("token", None)
        try:
            return self._dispatcher.dispatch(method, params)
        except PermissionError as error:
            raise ClientError({"code": -32004, "message": str(error)}) from error


def _sidecar(tmp_path: Path) -> tuple[Any, Any]:
    store = open_store(tmp_path / "graph")
    config = EffectiveConfig(state_root=str(tmp_path / "state"))
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    (tmp_path / "scope.json").write_text(json.dumps(scope_value()), encoding="utf-8")
    logger = StructuredLogger(logs / "runtime.jsonl", run_id=RUN_ID, component="ayran.test")
    artifact_store = ArtifactStore(tmp_path / "artifacts", allow_unsafe_filesystem=True)
    supervisor = ProcessSupervisor(
        tmp_path / "processes", run_id=RUN_ID, logger=logger, artifact_store=artifact_store
    )
    dispatcher = build_dispatcher(
        run_id=RUN_ID,
        config=config,
        store=store,
        logger=logger,
        artifact_store=artifact_store,
        process_supervisor=supervisor,
        receipt={"schema_version": "1.0.0", "run_id": RUN_ID, "run_state": "running"},
        state_root=tmp_path / "state",
        run_root=tmp_path,
    )
    return dispatcher, store


@pytest.fixture()
def engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    import ayran.skill.verbs as verbs

    dispatcher, store = _sidecar(tmp_path)
    # Activation-equivalent enrollment (§11.4/W7): the harness acts as the
    # extension client enrolling its generated session key.
    enrolled = dispatcher.dispatch(
        "credentials.enroll", {"key_b64": base64.b64encode(ENROLLMENT_KEY).decode("ascii")}
    )
    assert enrolled["accepted"] is True
    client = _InProcessClient(dispatcher)
    monkeypatch.setattr(verbs, "_connect", lambda: client)
    try:
        yield dispatcher
    finally:
        store.close()


def test_full_engagement_through_catalog_verbs(engagement: Any, tmp_path: Path) -> None:
    import ayran.skill.verbs as verbs

    dispatcher = engagement

    # 1. map_target: maps.build -> coverage.summary -> context.compile.
    mapped = verbs.map_target()
    assert mapped["schema_version"] == "1.0.0"
    assert mapped["maps"]["map_type"] == "attack_surface"
    assert mapped["coverage"]["schema_version"] == "1.0.0"
    assert mapped["pack"]["content_hash"].startswith("sha256:")

    # 2. remember: model-authored hypothesis through the ONLY write verb.
    remembered = verbs.remember(
        origin="model_novel",
        claim=CLAIM,
        attack_path=["enter withdraw()", "re-enter via fallback before zeroing", "profit: double withdrawal"],
        preconditions=[
            {"description": "attacker contract with payable fallback", "attacker_can_create": True},
            {"description": "vault holds pooled deposits", "attacker_can_create": False},
        ],
        violated_invariant="balances[msg.sender] is zeroed before any external call",
        cluster_id=CLUSTER,
        session=SESSION,
        resource="target/src",
    )
    assert remembered["accepted"] is True
    assert remembered["status"] == "lead"
    assert remembered["writer"] == {"kind": "model", "id": f"prime:{SESSION}"}
    hypothesis_id = str(remembered["hypothesis_id"])

    # 3. search_precedents: ingested corpus only. This fixture has no corpus
    #    release, so the verb surfaces the honest offline denial unchanged
    #    (the live Solodit POST stays operator-sanctioned-only).
    precedents = verbs.search_precedents("reentrancy", limit=5)
    assert precedents["accepted"] is False
    assert precedents["error"]["code"] == "CORPUS_UNAVAILABLE"

    # 4. scan: fixture adapter through tools.run (scripted seam; real adapters
    #    need the WSL toolchain — see honest-scope docstring).
    async def _fixture_run_capability(
        registry: Any,
        capability_id: str,
        payload: dict[str, Any],
        *,
        policy: Any,
        context: Any,
        require_available: bool = True,
    ) -> dict[str, Any]:
        from ayran.graph.canonical import utc_now
        from ayran.tools.runner import build_tool_run
        from ayran.tools.types import ZERO_HASH, RawRun

        stdout = json.dumps({"fixture": capability_id, "input_keys": sorted(payload)}).encode("utf-8")
        raw = RawRun(
            argv=["python", "-c", "print('r5 fixture adapter')"],
            cwd=None,
            env_fingerprint="fixture",
            started_at=utc_now(),
            ended_at=utc_now(),
            exit_code=0,
            signal=None,
            stdout=stdout,
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_hash="sha256:" + hashlib.sha256(stdout).hexdigest(),
            stderr_hash="sha256:" + hashlib.sha256(b"").hexdigest(),
            output_file_hashes={},
            input_hashes=[ZERO_HASH],
            executable_hash=None,
            timeout=False,
            failure_type=None,
        )
        tool_run = build_tool_run(
            registry=registry,
            capability_id=capability_id,
            raw=raw,
            parsed=None,
            parse_error=None,
            context=context,
            policy=policy,
            env_map={"PATH": "", "HOME": ""},
        )
        return {"tool_run": tool_run, "parsed": None}

    import ayran.tools.runner as runner_module

    original_run_capability = runner_module.run_capability
    runner_module.run_capability = _fixture_run_capability
    try:
        scanned = verbs.scan("solc.compile", {"source_paths": ["target/src/Vault.sol"]})
    finally:
        runner_module.run_capability = original_run_capability
    assert scanned["permitted"] is True
    assert scanned["tool_run"]["tool_run_id"].startswith("trn_")
    assert scanned["acknowledgement"]["commit_hash"].startswith("sha256:")

    # 5. attach_evidence: artifact stored + graph link, grade stays lead.
    attached = verbs.attach_evidence(
        hypothesis_id,
        "forge test output: attacker balance delta = +1 ETH after reentrant withdraw",
        kind="text",
    )
    assert attached["accepted"] is True
    assert attached["evidence_grade"] == "lead"
    assert attached["sha256"].startswith("sha256:")

    # Scripted-driver ladder step (never a catalog verb): lead -> supported.
    from m6_fixtures import TRUE_DEFECT_EVIDENCE

    promoted = dispatcher.dispatch(
        "evidence.transition",
        {
            "hypothesis_id": hypothesis_id,
            "to": "supported",
            "evidence": dict(TRUE_DEFECT_EVIDENCE),
            "actor": {"kind": "service", "id": "ayran.evidence", "version": "1.0.0"},
            "cause": "target-specific path and invariant",
        },
    )
    assert promoted["accepted"] is True

    # 6/7. spawn_challenger + request_gate_a: prepare (NO credential returned;
    #    the sidecar stopped minting) -> scripted transport -> deliver ->
    #    gate_a consumes the vaulted token with NO caller credential.
    from ayran.gates.credentials import CredentialAuthority
    from ayran.gates.spawn_challenger import ChallengerTransport
    from m6_fixtures import CHALLENGER_SUBMISSION_POC_WORTHY

    script = tmp_path / "scripted-challenger.json"
    script.write_text(json.dumps(dict(CHALLENGER_SUBMISSION_POC_WORTHY)), encoding="utf-8")
    authority = CredentialAuthority(ENROLLMENT_KEY)
    spawned = verbs.spawn_challenger(
        hypothesis_id,
        child_id="child-w11",
        transport=ChallengerTransport(script=script),
        credentials=authority,
    )
    assert spawned["credential_minter"] == "extension"
    assert "credential" not in spawned
    assert spawned["bundle"]["claim"] == CLAIM
    assert spawned["verdict"]["verdict"] == "poc_worthy"

    sealed = verbs.request_gate_a(
        hypothesis_id,
        submission=spawned["verdict"],
        child_id="child-w11",
        transcript_hash=str(spawned["transcript_hash"]),
    )
    assert sealed["verdict"] == "poc_worthy"
    assert sealed["record"]["reviewer"] == {"kind": "gate", "id": "rlm:child-w11", "version": "1.0.0"}

    # Scripted-driver ladder step (never a catalog verb): poc_worthy -> observed.
    from ayran.evidence.service import poc_run
    from m6_fixtures import recorded_poc_for_executed

    poc = poc_run(dispatcher.store, hypothesis_id, recorded=recorded_poc_for_executed(hypothesis_id))
    assert poc["status"] == "succeeded"

    # 8. request_gate_b with EXECUTED obligations -> defect_pinned + stamp.
    from ayran.gates.gate_b_mechanical import KRAIT_PASS
    from m6_fixtures import GATE_B_EXECUTED

    verdict_b = verbs.request_gate_b(
        hypothesis_id, poc_id=str(poc["poc_id"]), obligations=GATE_B_EXECUTED
    )
    assert verdict_b["verdict"] == "defect_pinned"
    assert verdict_b["krait_stamp"] == KRAIT_PASS

    # 9. coverage.
    posture = verbs.coverage()
    assert posture["schema_version"] == "1.0.0"
    assert "cells" in posture

    # 10. report: finding.build -> report.render -> report.lint.
    draft = verbs.report(hypothesis_id)
    assert draft["schema_version"] == "1.0.0"
    assert draft["finding"]["finding_id"].startswith("fnd_")
    assert "body" in draft["report"]
    assert draft["lint"]["finding_id"] == draft["finding"]["finding_id"]
    assert isinstance(draft["lint"], dict)

    # The whole engagement wrote through the single-writer boundary and the
    # journal verifies end-to-end.
    store = dispatcher.store
    verification = store.verify()
    assert verification["status"] == "ok"
    assert verification["issues"] == []
