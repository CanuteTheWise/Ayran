"""R1 — hypotheses.remember: model→graph write path (spec §5.1, §7, S9.1).

The golden template strings below are copied verbatim from the two templated
drivers deleted by R1 (hypotheses/drivers/model_native.py:54-57,81-84 and
hypotheses/drivers/adversarial_specialist.py:50-53,71-74) BEFORE deletion so
the S9.1 clause-3 inequality assertion stays runnable forever.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from ayran.artifacts.store import ArtifactStore
from ayran.bridge.handler import build_dispatcher
from ayran.compatibility.locks import check_compatibility
from ayran.config.models import EffectiveConfig
from ayran.evidence.load import load_hypotheses, load_hypothesis
from ayran.evidence.service import ORIGIN_WRITER_ALLOWLIST, remember
from ayran.gates.credentials import (
    CREDENTIAL_GRANT_REMEMBER,
    CredentialAuthority,
    CredentialError,
)
from ayran.process.supervisor import ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from m3_fixtures import scope_value
from m5_fixtures import RUN_ID, open_store

CLUSTER = "clus_01J00000000000000000000001"

# --- golden strings emitted by the DELETED template drivers (kept verbatim) ---
GOLDEN_MODEL_NATIVE_FUNCTION_CLAIM = (
    "First-principles: {function} may violate a value or authorization invariant "
    "on cluster {cluster} without retrieved or tool anchors."
)
GOLDEN_MODEL_NATIVE_EXPLORATION_CLAIM = (
    "First-principles exploration of cluster {cluster}: unknown invariants may be "
    "violated by unprivileged composition of in-scope entry points."
)
GOLDEN_SPECIALIST_BLIND_CLAIM = (
    "Specialist {role} ({mode}) reviews cluster {cluster} for "
    "independent diversity; historical names are excluded in blind mode."
)
GOLDEN_SPECIALIST_AWARE_CLAIM = (
    "Aware-phase specialist {role} re-evaluates cluster {cluster} "
    "after Global pack retrieval; disagreement with the blind pass is telemetry."
)
GOLDEN_TEMPLATE_INSTANCES = [
    GOLDEN_MODEL_NATIVE_FUNCTION_CLAIM.format(function="withdraw", cluster=CLUSTER),
    GOLDEN_MODEL_NATIVE_FUNCTION_CLAIM.format(function="deposit", cluster=CLUSTER),
    GOLDEN_MODEL_NATIVE_EXPLORATION_CLAIM.format(cluster=CLUSTER),
    GOLDEN_SPECIALIST_BLIND_CLAIM.format(role="bug-hunter", mode="blind", cluster=CLUSTER),
    GOLDEN_SPECIALIST_BLIND_CLAIM.format(role="econ-analyst", mode="aware", cluster=CLUSTER),
    GOLDEN_SPECIALIST_AWARE_CLAIM.format(role="devils-advocate", cluster=CLUSTER),
]

# A genuinely model-authored claim: specific mechanism, no template skeleton.
MODEL_AUTHORED_CLAIM = (
    "ReentrantVault.withdraw credits msg.sender only after the external call, so an "
    "attacker fallback can re-enter withdraw before balances are zeroed and drain "
    "the pool with two withdrawals for one deposit."
)

WRITER_IDS = {
    "model": "prime:sess-01j",
    "specialist": "rlm:child-01j",
    "service": "ayran.pipeline.census",
}


def _sidecar(tmp_path: Path) -> tuple[Any, Any]:
    store = open_store(tmp_path)
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


def _remember_params(**overrides: Any) -> dict[str, Any]:
    params: dict[str, Any] = {
        "origin": "model_novel",
        "claim": MODEL_AUTHORED_CLAIM,
        "attack_path": ["enter withdraw()", "re-enter via fallback before zeroing", "profit: double withdrawal"],
        "preconditions": [
            {"description": "attacker contract with payable fallback", "attacker_can_create": True},
            {"description": "vault holds pooled deposits", "attacker_can_create": False},
        ],
        "violated_invariant": "balances[msg.sender] is zeroed before any external call",
        "cluster_id": CLUSTER,
        "session": "sess-01j",
    }
    params.update(overrides)
    return params


class ScriptedActivation:
    """Deterministic CI driver: fixed turns against the in-process sidecar fixture."""

    def __init__(self, dispatcher: Any) -> None:
        self.dispatcher = dispatcher
        self.turns_used = 0
        self.remember_result: dict[str, Any] | None = None
        self.remember_method: str | None = None

    def turn(self, index: int) -> None:
        self.turns_used += 1
        if index == 1:
            # Activation: doctor across the real compatibility/locks loader.
            doctor = self.dispatcher.dispatch("run.doctor", {})
            assert doctor["schema_version"] == "1.0.0"
        elif index == 2:
            # The model authors its first hypothesis through the RPC surface.
            self.remember_method = "hypotheses.remember"
            self.remember_result = self.dispatcher.dispatch(
                "hypotheses.remember", _remember_params()
            )
        else:
            # Spare turn: the loop stops as soon as the hypothesis exists.
            self.dispatcher.dispatch("run.status", {})


def test_first_model_hypothesis_within_three_turns(tmp_path: Path) -> None:
    dispatcher, store = _sidecar(tmp_path)
    try:
        driver = ScriptedActivation(dispatcher)
        for turn in range(1, 4):
            driver.turn(turn)
            if driver.remember_result is not None and driver.remember_result.get("accepted"):
                break
        assert driver.turns_used <= 3

        # Clause (i): R0-fixed compatibility checks green via the real locks loader
        # (full doctor exit-0 on ext4 stays owner-witnessed per S9.1).
        checks = check_compatibility(EffectiveConfig(state_root=str(tmp_path / "state")))
        assert checks["prime_lock_present"] is True
        assert checks["platform_lock_present"] is True
        assert checks["version_alignment"] is True
        assert checks["prime_lock_provenance"] is True

        # Clause (ii): node exists with writer.kind == "model", origin model_novel,
        # created via the "hypotheses.remember" RPC method.
        assert driver.remember_method == "hypotheses.remember"
        result = driver.remember_result
        assert result is not None and result["accepted"] is True
        assert result["status"] == "lead"
        assert result["writer"] == {"kind": "model", "id": "prime:sess-01j"}
        hypothesis = load_hypothesis(store, str(result["hypothesis_id"]))
        assert hypothesis is not None
        assert hypothesis["origin"] == "model_novel"
        assert hypothesis["status"] == "lead"
        creation = hypothesis["transition_history"][0]
        assert creation["to"] == "lead"
        assert creation["actor"]["kind"] == "model"
        assert creation["actor"]["id"] == "prime:sess-01j"

        # Clause (iii): the claim differs from EVERY string the deleted template
        # drivers emitted (golden constants embedded above).
        claim = str(hypothesis["claim"])
        for golden in GOLDEN_TEMPLATE_INSTANCES:
            assert claim != golden
        assert "First-principles:" not in claim
        assert "reviews cluster" not in claim
        assert "Aware-phase specialist" not in claim

        # Clause (iv): the journal event chain verifies end-to-end.
        verification = store.verify()
        assert verification["status"] == "ok"
        assert verification["issues"] == []
        assert verification["verified_events"] >= 1
    finally:
        store.close()


def test_origin_writer_matrix_every_cell(tmp_path: Path) -> None:
    """INV-5.1: every origin x writer-kind allowlist cell is exercised."""

    store = open_store(tmp_path)
    try:
        cells = [
            (origin, kind)
            for origin in ORIGIN_WRITER_ALLOWLIST
            for kind in ("model", "specialist", "service")
        ]
        assert len(cells) == 18
        for origin, kind in cells:
            allowed = ORIGIN_WRITER_ALLOWLIST[origin]
            expected_ok = allowed is None or kind in allowed
            claim = f"{origin} hypothesis authored through the {kind} writer channel."
            outcome: dict[str, Any] | None = None
            failure: Exception | None = None
            try:
                outcome = remember(
                    store,
                    origin=origin,
                    claim=claim,
                    attack_path=["enter", "mutate", "profit"],
                    preconditions=[{"description": "unprivileged caller", "attacker_can_create": True}],
                    cluster_id=CLUSTER,
                    writer={"kind": kind, "id": WRITER_IDS[kind]},
                    session="sess-01j",
                )
            except Exception as error:
                failure = error
            if expected_ok:
                assert outcome is not None and failure is None, (origin, kind, failure)
                assert outcome["accepted"] is True
                assert outcome["writer"]["kind"] == kind
            else:
                from ayran.evidence.errors import ORIGIN_WRITER_DENIED

                assert failure is not None, (origin, kind, outcome)
                assert getattr(failure, "code", None) == ORIGIN_WRITER_DENIED, (origin, kind)
        # No service-writer may create origin=model_novel (INV-5.1 headline).
        from ayran.evidence.errors import ORIGIN_WRITER_DENIED, EvidenceError

        with pytest.raises(EvidenceError) as raised:
            remember(
                store,
                origin="model_novel",
                claim="service-forged model novel claim",
                attack_path=["enter", "mutate", "profit"],
                preconditions=[{"description": "unprivileged caller", "attacker_can_create": True}],
                cluster_id=CLUSTER,
                writer={"kind": "service", "id": "ayran.pipeline.census"},
                session="sess-01j",
            )
        assert raised.value.code == ORIGIN_WRITER_DENIED
    finally:
        store.close()


def test_client_supplied_writer_mismatch_is_impersonation(tmp_path: Path) -> None:
    from ayran.evidence.errors import WRITER_IMPERSONATION
    from ayran.evidence.load import load_nodes_by_type, node_props

    dispatcher, store = _sidecar(tmp_path)
    try:
        result = dispatcher.dispatch(
            "hypotheses.remember",
            _remember_params(writer={"kind": "model", "id": "prime:someone-else"}),
        )
        assert result["accepted"] is False
        assert result["error"]["code"] == WRITER_IMPERSONATION
        # The attempt is journaled.
        events = [
            node_props(node)
            for node in load_nodes_by_type(store, "SessionTransition")
            if node_props(node).get("event_type") == "writer_impersonation_denied"
        ]
        assert events, "writer impersonation denial was not journaled"
        assert load_hypotheses(store) == []
    finally:
        store.close()


def test_duplicate_returns_existing_hypothesis_id(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        first = remember(
            store,
            origin="model_novel",
            claim=MODEL_AUTHORED_CLAIM,
            attack_path=["enter withdraw()", "re-enter via fallback", "profit"],
            preconditions=[{"description": "fallback contract", "attacker_can_create": True}],
            cluster_id=CLUSTER,
            writer={"kind": "model", "id": "prime:sess-01j"},
            session="sess-01j",
        )
        second = remember(
            store,
            origin="model_novel",
            claim=MODEL_AUTHORED_CLAIM,
            attack_path=["enter withdraw()", "re-enter via fallback", "profit"],
            preconditions=[{"description": "fallback contract", "attacker_can_create": True}],
            cluster_id=CLUSTER,
            writer={"kind": "model", "id": "prime:sess-01j"},
            session="sess-01j",
        )
        assert first["dedup_result"]["status"] == "unique"
        assert second["dedup_result"]["status"] == "duplicate"
        assert second["hypothesis_id"] == first["hypothesis_id"]
        assert len(load_hypotheses(store)) == 1
    finally:
        store.close()


def test_claim_over_2048_chars_rejected(tmp_path: Path) -> None:
    from ayran.evidence.errors import REMEMBER_CONTRACT_INVALID, EvidenceError

    store = open_store(tmp_path)
    try:
        with pytest.raises(EvidenceError) as raised:
            remember(
                store,
                origin="model_novel",
                claim="x" * 2049,
                attack_path=["enter", "mutate", "profit"],
                preconditions=[{"description": "caller", "attacker_can_create": True}],
                cluster_id=CLUSTER,
                writer={"kind": "model", "id": "prime:sess-01j"},
                session="sess-01j",
            )
        assert raised.value.code == REMEMBER_CONTRACT_INVALID
    finally:
        store.close()


def test_session_writer_credentials_mint_verify_expire() -> None:
    now = 1000.0
    authority = CredentialAuthority(b"test-key", clock=lambda: now)
    token = authority.mint_session_writer(
        session="sess-01j", writer_kind="specialist", writer_id="rlm:child-01j"
    )
    payload = authority.verify(token, grant=CREDENTIAL_GRANT_REMEMBER)
    assert payload["writer"] == {"kind": "specialist", "id": "rlm:child-01j"}
    # Expired token reuse is denied.
    now = 2000.0
    with pytest.raises(CredentialError) as raised:
        authority.verify(token, grant=CREDENTIAL_GRANT_REMEMBER)
    assert raised.value.reason == "EXPIRED"
    # Wrong grant is denied.
    other = CredentialAuthority(b"test-key", clock=lambda: 1000.0)
    with pytest.raises(CredentialError):
        other.verify(other.mint(grants=("gate_a_submission",)), grant=CREDENTIAL_GRANT_REMEMBER)
    # Foreign key signature is denied.
    stranger = CredentialAuthority(b"other-key", clock=lambda: 1000.0)
    with pytest.raises(CredentialError):
        stranger.verify(token, grant=CREDENTIAL_GRANT_REMEMBER)


def test_remember_via_credential_bound_specialist_writer(tmp_path: Path) -> None:
    dispatcher, store = _sidecar(tmp_path)
    try:
        enrolled = dispatcher.dispatch(
            "credentials.enroll",
            {"key_b64": base64.b64encode(b"a-fixed-32-byte-test-key-aaaaaaa").decode()},
        )
        assert enrolled["accepted"] is True
        token = dispatcher.credentials.mint_session_writer(
            session="sess-02j", writer_kind="specialist", writer_id="rlm:child-02j"
        )
        result = dispatcher.dispatch(
            "hypotheses.remember",
            _remember_params(
                origin="specialist",
                claim="Specialist-derived: the oracle freshness window lets stale quotes be replayed during liquidation.",
                credential=token,
                session="sess-02j",
            ),
        )
        assert result["accepted"] is True
        assert result["writer"] == {"kind": "specialist", "id": "rlm:child-02j"}
        hypothesis = load_hypothesis(store, str(result["hypothesis_id"]))
        assert hypothesis is not None
        assert hypothesis["transition_history"][0]["actor"]["id"] == "rlm:child-02j"
    finally:
        store.close()
