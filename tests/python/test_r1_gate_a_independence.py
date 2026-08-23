"""R1 — Gate A independence (spec §5.5, §11.4, S9.2).

Binary checks named by the completion spec:
* ``test_reviewer_identity_and_zero_leakage`` (S9.2 clauses 1-2)
* ``test_forced_verdict_rejected`` (S9.2 clause 3)

CI determinism: the challenger runs behind a scripted transport seam — a real
short-lived subprocess reading the blind bundle on stdin and writing its
scripted verdict JSON to stdout. The LIVE ``rlm()`` round trip is the
owner-witnessed demo-of-done performed after verification.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from ayran.evidence.errors import VERDICT_OVERRIDE_FORBIDDEN, EvidenceError
from ayran.evidence.load import (
    load_hypothesis,
    load_nodes_by_type,
    load_verdicts_for,
    node_props,
)
from ayran.evidence.persist import evidence_node, persist_runtime_node
from ayran.evidence.service import remember, transition
from ayran.gates.credentials import CredentialAuthority
from ayran.gates.spawn_challenger import (
    ChallengerTransport,
    build_challenger_bundle,
    forbidden_leakage_tokens,
    leakage_scan,
    spawn_challenger,
)
from m5_fixtures import RUN_ID, open_store
from m6_fixtures import (
    CHALLENGER_SUBMISSION_POC_WORTHY,
    TRUE_DEFECT_EVIDENCE,
    promote_supported,
)

CLUSTER = "clus_01J00000000000000000000001"
CLAIM = (
    "ReentrantVault.withdraw credits msg.sender only after the external call, so an "
    "attacker fallback can re-enter withdraw before balances are zeroed and drain "
    "the pool with two withdrawals for one deposit."
)
SUPPORTED_EVIDENCE = dict(TRUE_DEFECT_EVIDENCE)


def _model_hypothesis_supported(store: Any, claim: str = CLAIM) -> str:
    created = remember(
        store,
        origin="model_novel",
        claim=claim,
        attack_path=["enter withdraw()", "re-enter via fallback before zeroing", "profit"],
        preconditions=[
            {"description": "attacker contract with payable fallback", "attacker_can_create": True}
        ],
        violated_invariant="balances[msg.sender] is zeroed before any external call",
        cluster_id=CLUSTER,
        writer={"kind": "model", "id": "prime:sess-01j"},
        session="sess-01j",
    )
    hypothesis_id = str(created["hypothesis_id"])
    transition(
        store,
        hypothesis_id,
        "supported",
        evidence=SUPPORTED_EVIDENCE,
        actor={"kind": "service", "id": "ayran.evidence", "version": "1.0.0"},
        cause="target-specific path and invariant",
    )
    return hypothesis_id


def _seed_historical_card(store: Any) -> dict[str, str]:
    node = evidence_node(
        node_type="MechanismCard",
        node_id=f"nod_01J{'0' * 21}HK",
        run_id=RUN_ID,
        created_at="2026-08-12T12:00:00Z",
        source_locator="global:mechanism:reentrancy-guard-miss",
        properties={"title": "reentrancy-guard-miss-2019-card", "classification": "HISTORICAL_REFERENCE"},
    )
    persist_runtime_node(store, node, actor={"kind": "service", "id": "ayran.knowledge", "version": "1.0.0"})
    return {"node_id": node["node_id"], "title": "reentrancy-guard-miss-2019-card"}


def _script_file(tmp_path: Path, submission: dict[str, Any]) -> Path:
    path = tmp_path / "scripted-challenger.json"
    path.write_text(json.dumps(submission), encoding="utf-8")
    return path


def test_reviewer_identity_and_zero_leakage(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        hypothesis_id = _model_hypothesis_supported(store)
        historical = _seed_historical_card(store)

        # S9.2 clause 1: reviewer identity is stamped by the evidence service
        # from the submission credential after a real challenger round trip.
        authority = CredentialAuthority(b"r1-s9-auth")
        result = spawn_challenger(
            hypothesis_id,
            store=store,
            credentials=authority,
            transport=ChallengerTransport(script=_script_file(tmp_path, dict(CHALLENGER_SUBMISSION_POC_WORTHY))),
            child_id="child-77",
        )
        assert result["verdict"] == "poc_worthy"
        record = result["record"]
        author = load_hypothesis(store, hypothesis_id)
        assert author is not None
        writer = author["transition_history"][0]["actor"]
        assert record["reviewer"] != writer
        assert record["reviewer"]["kind"] == "gate"
        assert record["reviewer"]["id"] == "rlm:child-77"
        assert record["independent_from"] == [hypothesis_id]
        assert result["record"]["resulting_hypothesis_status"] == "poc_worthy"

        # S9.2 clause 2: zero HISTORICAL_REFERENCE / Global Graph material in
        # the bundle, and the leakage scan reports count 0 in BOTH directions.
        bundle_json = json.dumps(result["bundle"], sort_keys=True)
        assert historical["node_id"] not in bundle_json
        assert historical["title"] not in bundle_json
        assert forbidden_leakage_tokens(store)
        scan = result["leakage_scan"]
        assert scan["count"] == 0
        assert scan["clean"] is True
        # Direct bidirectional rescan for the assertion's own evidence.
        rescan = leakage_scan(
            bundle_bytes=bundle_json.encode("utf-8"),
            verdict_text=json.dumps(record),
            forbidden_tokens=[historical["node_id"], historical["title"]],
        )
        assert rescan["count"] == 0 and rescan["clean"] is True

        # The credential is revoked at the verdict seal (single grant, §11.4).
        assert result["credential_state"]["used_credentials"] == 1
        # Blind verdict is sealed before reconciliation attaches (second
        # hypothesis: the first already transitioned to poc_worthy).
        second_id = _model_hypothesis_supported(store, claim=CLAIM + " (reconcile pass)")
        reconciled = spawn_challenger(
            second_id,
            store=store,
            credentials=authority,
            transport=ChallengerTransport(script=_script_file(tmp_path, dict(CHALLENGER_SUBMISSION_POC_WORTHY))),
            child_id="child-78",
            reconcile=True,
        )
        assert reconciled["reconciliation"]["blind_verdict_id"] == reconciled["verdict_id"]
        assert load_verdicts_for(store, hypothesis_id)
    finally:
        store.close()


def test_forced_verdict_rejected(tmp_path: Path) -> None:
    from m6_fixtures import seed_hypothesis

    store = open_store(tmp_path)
    try:
        hypothesis_id = _model_hypothesis_supported(store)
        before = load_hypothesis(store, hypothesis_id)

        # The exact old forced shape, submitted through the sidecar service.
        with pytest.raises(EvidenceError) as raised:
            from ayran.evidence.service import gate_a

            gate_a(
                store,
                hypothesis_id,
                analysis={"source": "contract X {}", "verdict": "poc_worthy"},
            )
        assert raised.value.code == VERDICT_OVERRIDE_FORBIDDEN
        with pytest.raises(EvidenceError) as proposed:
            gate_a(
                store,
                hypothesis_id,
                analysis={"proposed_verdict": "falsified"},
            )
        assert proposed.value.code == VERDICT_OVERRIDE_FORBIDDEN

        # Zero state transition and zero sealed verdicts.
        after = load_hypothesis(store, hypothesis_id)
        assert after is not None and before is not None
        assert after["status"] == before["status"] == "supported"
        assert after["transition_history"] == before["transition_history"]
        assert load_verdicts_for(store, hypothesis_id) == []

        # The attempt is journaled at the RPC boundary.
        from test_r1_hypothesis_remember import _sidecar

        dispatcher, rpc_store = _sidecar(tmp_path / "rpc")
        try:
            hyp = seed_hypothesis(rpc_store, claim="forced shape probe", root_cause="probe")
            promote_supported(rpc_store, hyp["hypothesis_id"])
            denial = dispatcher.dispatch(
                "evidence.gate_a",
                {
                    "hypothesis_id": str(hyp["hypothesis_id"]),
                    "analysis": {"source": "x", "verdict": "poc_worthy"},
                },
            )
            assert denial["accepted"] is False
            assert denial["error"]["code"] == VERDICT_OVERRIDE_FORBIDDEN
            events = [
                node_props(node)
                for node in load_nodes_by_type(rpc_store, "SessionTransition")
                if node_props(node).get("event_type") == "verdict_override_denied"
            ]
            assert events, "verdict override denial was not journaled"
        finally:
            rpc_store.close()
    finally:
        store.close()


def test_invariant_floor_forces_reformulation(tmp_path: Path) -> None:
    """E3: violated_invariant under the 12-char floor structurally forces
    needs_reformulation (floor rule, not verdict synthesis)."""

    store = open_store(tmp_path)
    try:
        hypothesis_id = _model_hypothesis_supported(store)
        submission = dict(CHALLENGER_SUBMISSION_POC_WORTHY)
        submission["violated_invariant"] = "too short"
        authority = CredentialAuthority(b"r1-s9-auth")
        result = spawn_challenger(
            hypothesis_id,
            store=store,
            credentials=authority,
            transport=ChallengerTransport(script=_script_file(tmp_path, submission)),
            child_id="child-79",
        )
        assert result["verdict"] == "needs_reformulation"
        assert result["record"]["resulting_hypothesis_status"] == "needs_reformulation"
    finally:
        store.close()


def test_credential_single_use_and_expiry(tmp_path: Path) -> None:
    """E3: expired-token reuse denied; a second submission on a consumed token
    is denied and journaled at the RPC boundary."""

    from ayran.evidence.errors import CREDENTIAL_DENIED

    store = open_store(tmp_path)
    try:
        hypothesis_id = _model_hypothesis_supported(store)
        now = 1000.0
        authority = CredentialAuthority(b"r1-s9-auth", clock=lambda: now)
        token = authority.mint_challenger(child_id="child-80", ttl_seconds=50.0)
        from ayran.evidence.service import gate_a

        first = gate_a(
            store,
            hypothesis_id,
            submission=dict(CHALLENGER_SUBMISSION_POC_WORTHY),
            credential=token,
            credentials=authority,
        )
        assert first["verdict"] == "poc_worthy"
        # Reuse of the consumed (revoked-at-seal) token is denied.
        with pytest.raises(EvidenceError) as reuse:
            gate_a(
                store,
                hypothesis_id,
                submission=dict(CHALLENGER_SUBMISSION_POC_WORTHY),
                credential=token,
                credentials=authority,
            )
        assert reuse.value.code == CREDENTIAL_DENIED
        # Expired token is denied.
        expired = CredentialAuthority(b"r1-s9-auth", clock=lambda: 5000.0)
        stale = CredentialAuthority(b"r1-s9-auth", clock=lambda: now).mint_challenger(
            child_id="child-81", ttl_seconds=50.0
        )
        with pytest.raises(EvidenceError) as stale_denial:
            gate_a(
                store,
                hypothesis_id,
                submission=dict(CHALLENGER_SUBMISSION_POC_WORTHY),
                credential=stale,
                credentials=expired,
            )
        assert stale_denial.value.code == CREDENTIAL_DENIED
    finally:
        store.close()


def test_bundle_carries_claim_and_target_slice_only(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        hypothesis_id = _model_hypothesis_supported(store)
        historical = _seed_historical_card(store)
        bundle = build_challenger_bundle(store, hypothesis_id)
        assert set(bundle) == {
            "schema_version",
            "hypothesis_id",
            "claim",
            "attack_path",
            "preconditions",
            "violated_invariant",
            "target_source_slices",
        } | ({"invariant_ids"} if bundle.get("invariant_ids") else set())
        serialized = json.dumps(bundle, sort_keys=True)
        assert historical["node_id"] not in serialized
        assert historical["title"] not in serialized
    finally:
        store.close()


def test_default_scripted_challenger_is_deterministic(tmp_path: Path) -> None:
    """Without a script file the subprocess derives a valid stand-in verdict
    from the bundle alone — deterministic, no model, no network."""

    store = open_store(tmp_path)
    try:
        hypothesis_id = _model_hypothesis_supported(store)
        authority = CredentialAuthority(b"r1-s9-auth")
        result = spawn_challenger(
            hypothesis_id, store=store, credentials=authority, child_id="child-82"
        )
        assert result["verdict"] in {"poc_worthy", "needs_missing_fact", "needs_reformulation", "falsified"}
        assert result["leakage_scan"]["count"] == 0
    finally:
        store.close()


# --- §11.2 isolation: fail-closed probe, degraded headless mode, tamper -------


def test_isolation_probe_records_process_boundary_facts(tmp_path: Path) -> None:
    from ayran.gates.isolation import verify_isolation

    report = verify_isolation(
        state_root=tmp_path / "state",
        spool_root=tmp_path / "challenger-spool",
        included_roots=["target/src"],
        transport_facts={"channel": "subprocess", "writable_roots": [], "has_sidecar_socket": False},
        credential_grants=["gate_a_submission"],
    )
    assert report["verified"] is True
    assert report["mode"] == "verified_subprocess"
    assert report["facts"]["transport"]["channel"] == "subprocess"

    # Each probe clause fails closed when violated.
    inside = verify_isolation(
        state_root=tmp_path / "state",
        spool_root=tmp_path / "state" / "spool",
        transport_facts={"channel": "subprocess"},
        credential_grants=["gate_a_submission"],
    )
    assert inside["verified"] is False
    assert any("OUTSIDE the state root" in item for item in inside["refusals"])
    in_process = verify_isolation(
        state_root=tmp_path / "state",
        spool_root=tmp_path / "spool",
        transport_facts={"channel": "in_process"},
        credential_grants=["gate_a_submission"],
    )
    assert in_process["verified"] is False
    assert any("isolated process boundary" in item for item in in_process["refusals"])
    socketed = verify_isolation(
        state_root=tmp_path / "state",
        spool_root=tmp_path / "spool",
        transport_facts={"channel": "subprocess", "has_sidecar_socket": True},
        credential_grants=["gate_a_submission"],
    )
    assert socketed["verified"] is False
    assert any("sidecar socket" in item for item in socketed["refusals"])
    broad = verify_isolation(
        state_root=tmp_path / "state",
        spool_root=tmp_path / "spool",
        transport_facts={"channel": "subprocess"},
        credential_grants=["gate_a_submission", "hypotheses.remember"],
    )
    assert broad["verified"] is False
    assert any("exceed the declared client scope" in item for item in broad["refusals"])


def test_tampered_isolation_refuses_cognitive_methods(tmp_path: Path) -> None:
    """§11.2 tamper test: with isolation deliberately broken via fixture flag,
    startup refuses cognitive methods with the defined error; nothing is sealed."""

    from ayran.evidence.errors import ISOLATION_UNVERIFIED
    from test_r1_hypothesis_remember import _remember_params, _sidecar

    dispatcher, store = _sidecar(tmp_path / "tampered")
    try:
        assert dispatcher.isolation_report()["verified"] is True
        dispatcher.isolation_tampered = True  # fixture flag breaks the boundary
        broken = dispatcher.run_isolation_probe()
        assert broken["verified"] is False
        assert broken["refusals"]

        remembered = dispatcher.dispatch("hypotheses.remember", _remember_params())
        assert remembered["accepted"] is False
        assert remembered["error"]["code"] == ISOLATION_UNVERIFIED
        from ayran.evidence.load import load_hypotheses
        from ayran.evidence.load import load_nodes_by_type as _lnt

        assert load_hypotheses(store) == []
        denial = dispatcher.dispatch(
            "evidence.gate_a",
            {
                "hypothesis_id": "hyp_01J00000000000000000000001",
                "submission": dict(CHALLENGER_SUBMISSION_POC_WORTHY),
                "credential": "x.y",
            },
        )
        assert denial["accepted"] is False
        assert denial["error"]["code"] == ISOLATION_UNVERIFIED
        assert load_verdicts_for(store, "hyp_01J00000000000000000000001") == []
        refusals = [
            node_props(node)
            for node in _lnt(store, "SessionTransition")
            if node_props(node).get("event_type") == "isolation_refusal"
        ]
        assert refusals, "isolation refusal was not journaled"
    finally:
        store.close()


def test_degraded_headless_mode_seals_transcript_hash(tmp_path: Path) -> None:
    """§11.2 degraded fallback: headless session, verdict in the sidecar-owned
    spool directory OUTSIDE the state root and included_roots, mode 0600 on
    POSIX, and the spool file's transcript hash bound into the sealed record."""

    import os

    from ayran.gates.isolation import degraded_headless_facts, verify_isolation
    from ayran.gates.spawn_challenger import HeadlessChallengerTransport

    state_root = tmp_path / "state"
    spool_root = tmp_path / "state-sibling-spool"
    facts = degraded_headless_facts(target_copy_root=tmp_path / "target-copy")
    probe = verify_isolation(
        state_root=state_root,
        spool_root=spool_root,
        included_roots=["target/src"],
        transport_facts=facts,
        credential_grants=["gate_a_submission"],
    )
    assert probe["verified"] is True
    assert probe["mode"] == "degraded_headless"

    store = open_store(tmp_path / "graph")
    try:
        hypothesis_id = _model_hypothesis_supported(store)
        authority = CredentialAuthority(b"r1-s9-auth")
        result = spawn_challenger(
            hypothesis_id,
            store=store,
            credentials=authority,
            transport=HeadlessChallengerTransport(
                script=_script_file(tmp_path, dict(CHALLENGER_SUBMISSION_POC_WORTHY)),
                target_copy_root=tmp_path / "target-copy",
            ),
            child_id="child-90",
            spool_root=spool_root,
        )
        assert result["verdict"] == "poc_worthy"
        spool = result["spool"]
        assert Path(spool["spool_path"]).is_file()
        assert state_root not in Path(spool["spool_path"]).resolve().parents
        if os.name != "nt":
            assert (Path(spool["spool_path"]).stat().st_mode & 0o777) == 0o600
        # The transcript hash from the spool file is bound into the sealed record.
        provenance = result["record"]["provenance"][0]
        assert provenance["raw_hash"] == spool["transcript_hash"]
        assert provenance["raw_hash"].startswith("sha256:")
    finally:
        store.close()


def test_challenger_prepare_rpc_round_trip(tmp_path: Path) -> None:
    """Root-skill transport seam over RPC: challenger.prepare returns the
    blind bundle (extension is the minter); the extension vaults the
    child-bound token via credentials.deliver; evidence.gate_a omits the
    credential and consumes the vault at seal. Equal-or-stronger than the
    pre-R5 prepare-returns-credential flow: mint is extension-side, the
    model never handles a challenger token, and vault consumption is
    asserted on replay."""

    from test_r1_hypothesis_remember import MODEL_AUTHORED_CLAIM, _remember_params, _sidecar

    dispatcher, store = _sidecar(tmp_path / "prepare")
    test_key = b"a-fixed-32-byte-test-key-aaaaaaa"
    try:
        created = dispatcher.dispatch("hypotheses.remember", _remember_params())
        assert created["accepted"] is True
        from ayran.evidence.service import transition
        from m6_fixtures import TRUE_DEFECT_EVIDENCE as EVIDENCE

        transition(
            store,
            str(created["hypothesis_id"]),
            "supported",
            evidence=dict(EVIDENCE),
            actor={"kind": "service", "id": "ayran.evidence", "version": "1.0.0"},
            cause="target-specific path and invariant",
        )
        enrolled = dispatcher.dispatch(
            "credentials.enroll",
            {"key_b64": base64.b64encode(test_key).decode()},
        )
        assert enrolled["accepted"] is True
        prepared = dispatcher.dispatch(
            "challenger.prepare",
            {"hypothesis_id": str(created["hypothesis_id"]), "child_id": "child-91"},
        )
        assert prepared["schema_version"] == "1.0.0"
        assert prepared["credential_minter"] == "extension"
        assert prepared["isolation"]["verified"] is True
        assert prepared["bundle"]["claim"] == MODEL_AUTHORED_CLAIM
        assert "credential" not in prepared
        token = CredentialAuthority(test_key).mint_challenger(child_id="child-91")
        delivered = dispatcher.dispatch(
            "credentials.deliver",
            {"child_id": "child-91", "credential": token},
        )
        assert delivered["accepted"] is True
        verdict = dispatcher.dispatch(
            "evidence.gate_a",
            {
                "hypothesis_id": str(created["hypothesis_id"]),
                "submission": dict(CHALLENGER_SUBMISSION_POC_WORTHY),
                "child_id": "child-91",
            },
        )
        assert verdict["verdict"] == "poc_worthy"
        assert verdict["record"]["reviewer"]["id"] == "rlm:child-91"
        replay = dispatcher.dispatch(
            "evidence.gate_a",
            {
                "hypothesis_id": str(created["hypothesis_id"]),
                "submission": dict(CHALLENGER_SUBMISSION_POC_WORTHY),
                "child_id": "child-91",
            },
        )
        assert replay["accepted"] is False
        assert replay["error"]["code"] == "CREDENTIAL_DENIED"
    finally:
        store.close()
