"""R2 — Gate B is mechanical, not honor-system (spec §5.6, S9.3, INV-5.6/5.7/5.10).

Binary checks named by the completion spec:
* ``test_forged_pass_needs_reformulation`` (S9.3 c1)
* ``test_executed_obligations_defect_pinned_with_hashes`` (S9.3 c2)

CI determinism: every mechanical rule is exercised through the ScriptedRunner
seam — recorded fixture runs replayed verbatim through the same parse/hash/
classify/stamp pipeline a live ForgeRunner uses. Real forge runs belong to the
owner's WSL demo-of-done; no forge invocation, network, wallets, or keys here.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from ayran.evidence.errors import OBLIGATION_FORGERY_REJECTED
from ayran.gates.gate_b_mechanical import (
    KRAIT_PASS,
    KRAIT_UNPINNED,
    ScriptedRunner,
    artifact_hashes,
    classify_runs,
    detect_forgery,
    execute_runs,
    patch_scope_violations,
    summary_hash,
)
from m6_fixtures import (
    CONTROL_RUN_BLOCK,
    GATE_B_EXECUTED,
    REPLAY_FORGE_JSON,
    REPLAY_RUN_BLOCK,
    forge_json_suite,
)


def _runs(payload: dict[str, Any]) -> Any:
    return execute_runs(payload, ScriptedRunner())


# --- E4: canonical hashing over normalized summaries, never raw stdout ------


def test_stdout_hash_is_canonicalized_not_raw() -> None:
    runs = _runs({"clean_replay": REPLAY_RUN_BLOCK})
    replay = runs.results["replay"]
    raw = json.dumps(REPLAY_FORGE_JSON).encode("utf-8")
    assert replay.stdout_sha256 != "sha256:" + hashlib.sha256(raw).hexdigest()
    assert replay.stdout_sha256 == summary_hash(replay.canonical_summary)
    # The summary is exactly test names + pass/fail + key numeric results.
    summary = json.loads(replay.canonical_summary)
    assert summary == [
        {"contract": "ExploitTest", "gas": 48213, "name": "test_exploit", "reason": None, "status": "pass"}
    ]


def test_equivalent_suites_hash_identically_regardless_of_formatting() -> None:
    left = _runs({"clean_replay": REPLAY_RUN_BLOCK}).results["replay"]
    # Same outcomes, different key order and capitalization, extra noise keys.
    noisy = {
        "test_results": {
            "ExploitTest": {"test_exploit": {"gas": 48213, "status": "Pass", "tracer": None}}
        }
    }
    noisy_runs = _runs({"clean_replay": {**REPLAY_RUN_BLOCK, "stdout_json": noisy}})
    assert left.stdout_sha256 == noisy_runs.results["replay"].stdout_sha256


# --- S9.3 c1 / INV-5.6: asserted booleans are rejected at parse time ---------


def test_forgery_detection_bare_pass_without_execution() -> None:
    forged = detect_forgery({"clean_replay": {"passed": True}})
    assert forged == ["clean_replay"]
    assert detect_forgery({"clean_replay": dict(REPLAY_RUN_BLOCK)}) == []
    # A claimed failure is an honor-system relic too, but not the c1 forgery.
    assert detect_forgery({"clean_replay": {"passed": False}}) == []
    assert detect_forgery({"alternate_paths": {"passed": True}}) == []


# --- §5.6 patch restriction: mechanical pre-check BEFORE execution -----------


def test_patch_scope_precheck_blocks_test_harness_config() -> None:
    def _payload(path: str) -> dict[str, Any]:
        return {
            "negative_controls": dict(CONTROL_RUN_BLOCK),
            "patch": {"files": [{"path": path, "content": "x"}]},
        }

    for path in (
        "test/Exploit.t.sol",
        "tests/ExploitTest.sol",
        "script/Deploy.s.sol",
        "harness/Harness.sol",
        "foundry.toml",
        "remappings.txt",
        "config/settings.json",
    ):
        assert patch_scope_violations(_payload(path)), path
    assert patch_scope_violations(_payload("src/ReentrantVault.sol")) == []
    # Pinning runs without any patch are unattributable.
    assert patch_scope_violations({"negative_controls": dict(CONTROL_RUN_BLOCK)})
    # Containment against the claim's source spans when supplied.
    scoped = _payload("src/Other.sol")
    scoped["allowed_source_files"] = ["src/ReentrantVault.sol"]
    assert patch_scope_violations(scoped)


# --- S9.3 c2 classification over the three decisive runs ---------------------


def test_three_genuine_runs_pin_the_defect() -> None:
    classification = classify_runs(GATE_B_EXECUTED, _runs(GATE_B_EXECUTED), match_test="test_exploit")
    assert classification.verdict == "defect_pinned"
    assert classification.krait_stamp == KRAIT_PASS
    assert classification.pinned is True
    assert classification.obligations["clean_replay"]["passed"] is True
    assert classification.obligations["negative_controls"]["passed"] is True
    assert classification.obligations["defect_removal"]["passed"] is True
    assert classification.obligations["fix_efficacy"]["passed"] is True
    # Every executed block carries the full §5.6 field set.
    for name, block in classification.executed_blocks.items():
        assert {"command", "argv", "cwd", "exit_code", "stdout_sha256", "duration_ms"} <= set(block), name


def test_control_failing_with_bare_nonzero_exit_does_not_satisfy() -> None:
    payload = dict(GATE_B_EXECUTED)
    payload["negative_controls"] = {
        **CONTROL_RUN_BLOCK,
        "stdout_json": forge_json_suite({"ExploitTest": {}}),  # nothing parsed
    }
    payload["defect_removal"] = dict(payload["negative_controls"])
    classification = classify_runs(payload, _runs(payload), match_test="test_exploit")
    assert classification.obligations["negative_controls"]["wrong_reason"] is True
    assert classification.obligations["negative_controls"]["passed"] is False
    assert classification.verdict == "needs_reformulation"


def test_compile_error_flip_classifies_needs_reformulation() -> None:
    payload = dict(GATE_B_EXECUTED)
    payload["negative_controls"] = {**CONTROL_RUN_BLOCK, "compile_error": True}
    payload["defect_removal"] = dict(payload["negative_controls"])
    classification = classify_runs(payload, _runs(payload), match_test="test_exploit")
    assert classification.obligations["defect_removal"]["compile_flip"] is True
    assert classification.obligations["defect_removal"]["passed"] is False
    assert classification.verdict == "needs_reformulation"
    assert classification.krait_stamp == KRAIT_UNPINNED  # replay still reproduced


def test_unmeasurable_coverage_fails_closed_to_unpinned() -> None:
    payload = dict(GATE_B_EXECUTED)
    payload["negative_controls"] = {key: value for key, value in CONTROL_RUN_BLOCK.items() if key != "coverage"}
    payload["defect_removal"] = dict(payload["negative_controls"])
    classification = classify_runs(payload, _runs(payload), match_test="test_exploit")
    assert classification.verdict == "needs_reformulation"
    assert classification.krait_stamp == KRAIT_UNPINNED
    assert "coverage not measurable" in classification.obligations["fix_efficacy"]["detail"]


def test_replay_hash_mismatch_falsifies() -> None:
    classification = classify_runs(
        GATE_B_EXECUTED,
        _runs(GATE_B_EXECUTED),
        match_test="test_exploit",
        expected_replay_hash="sha256:" + "0" * 64,
    )
    assert classification.verdict == "falsified"
    assert classification.obligations["clean_replay"]["mismatch"] is True


# --- INV-5.10 analog: mechanical-before-judgment ordering --------------------


def test_mechanical_before_judgment_all_runs_hashed_before_classification() -> None:
    runner = ScriptedRunner()
    runs = execute_runs(GATE_B_EXECUTED, runner)
    # All three executions completed (and were hashed into frozen results)
    # before classify_runs was callable on anything.
    assert runner.executions == ["replay", "patched", "revert_mutation"]
    assert set(runs.results) == set(runner.executions)
    for result in runs.results.values():
        assert result.stdout_sha256.startswith("sha256:")
    classification = classify_runs(runs=runs, payload=GATE_B_EXECUTED, match_test="test_exploit")
    assert classification.executed_blocks  # decisions consumed only hashed records


def test_failing_run_halts_before_any_classification() -> None:
    class ExplodingRunner(ScriptedRunner):
        def execute(self, slot: str, block: Any) -> Any:
            if slot == "patched":
                raise RuntimeError("run exploded mid-flight")
            return super().execute(slot, block)

    with pytest.raises(RuntimeError):
        execute_runs(GATE_B_EXECUTED, ExplodingRunner())


# --- E4: artifact hashes recompute over supplied bytes ------------------------


def test_artifact_hashes_recompute_over_bytes() -> None:
    entries = artifact_hashes(GATE_B_EXECUTED)
    by_kind = {entry["kind"]: entry for entry in entries}
    import hashlib as _hashlib

    from m6_fixtures import MUTATED_SOURCE_BYTES, POC_SOURCE_BYTES, TRACE_OUTPUT_BYTES

    assert by_kind["poc_source"]["sha256"] == "sha256:" + _hashlib.sha256(POC_SOURCE_BYTES).hexdigest()
    assert by_kind["trace_output"]["sha256"] == "sha256:" + _hashlib.sha256(TRACE_OUTPUT_BYTES).hexdigest()
    assert by_kind["mutated_source"]["sha256"] == "sha256:" + _hashlib.sha256(MUTATED_SOURCE_BYTES).hexdigest()


def test_genuine_payload_has_no_boolean_claims_on_executable_obligations() -> None:
    for name in ("clean_replay", "numerical_assertions", "negative_controls", "defect_removal", "fix_efficacy"):
        block = GATE_B_EXECUTED[name]
        assert "passed" not in block, name
        assert {"command", "exit_code"} <= set(block), name


# --- S9.3 c1 + c2 through the SERVICE boundary --------------------------------

_OBSERVED_CLAIM = (
    "ReentrantVault.withdraw is reentrant because the external call happens "
    "before balances are zeroed"
)


def _observed_hypothesis(store: Any, claim: str = _OBSERVED_CLAIM) -> str:
    """lead -> supported -> poc_worthy -> observed, with a canonical PocRun."""

    from ayran.evidence.service import poc_run
    from m6_fixtures import (
        CHALLENGER_SUBMISSION_POC_WORTHY,
        TRUE_DEFECT_EVIDENCE,
        challenger_gate_a,
        promote_supported,
        recorded_poc_for_executed,
        seed_hypothesis,
    )

    hyp = seed_hypothesis(store, claim=claim, root_cause="reentrancy-call-before-zero")
    hid = str(hyp["hypothesis_id"])
    promote_supported(store, hid, TRUE_DEFECT_EVIDENCE)
    verdict = challenger_gate_a(store, hid, dict(CHALLENGER_SUBMISSION_POC_WORTHY))
    assert verdict["verdict"] == "poc_worthy"
    poc = poc_run(store, hid, recorded=recorded_poc_for_executed(hid))
    assert poc["status"] == "succeeded"
    return hid


def test_forged_pass_needs_reformulation(tmp_path: Path) -> None:
    """S9.3 c1: the exact honor-system abuse, through the service boundary."""

    from ayran.evidence.load import (
        load_hypothesis,
        load_nodes_by_type,
        load_verdicts_for,
        node_props,
    )
    from ayran.evidence.service import gate_b
    from m6_fixtures import open_store

    store = open_store(tmp_path)
    try:
        hid = _observed_hypothesis(store)
        before = load_hypothesis(store, hid)
        assert before is not None and before["status"] == "observed"

        result = gate_b(
            store,
            hid,
            obligations={"clean_replay": {"passed": True}},
            caller={"kind": "model", "id": "prime:sess-r2"},
        )
        assert result["verdict"] == "needs_reformulation"
        assert result["record"] is None
        assert result["forgery_rejected"] is True
        assert result["error"]["code"] == OBLIGATION_FORGERY_REJECTED

        # Zero promotion: the hypothesis node is byte-equal.
        after = load_hypothesis(store, hid)
        assert after is not None
        assert json.dumps(after, sort_keys=True) == json.dumps(before, sort_keys=True)
        # Zero sealed Gate B verdict records of either schema.
        assert [item for item in load_verdicts_for(store, hid) if item.get("gate") == "B"] == []
        assert load_nodes_by_type(store, "GateBExecutionRecord") == []
        # The forgery is journaled NAMING the caller identity.
        events = [
            node_props(node)
            for node in load_nodes_by_type(store, "SessionTransition")
            if node_props(node).get("event_type") == "obligation_forgery_rejected"
        ]
        assert events, "obligation forgery was not journaled"
        assert "prime:sess-r2" in str(events[0].get("payload_json"))
        assert "clean_replay" in str(events[0].get("payload_json"))
    finally:
        store.close()


def test_executed_obligations_defect_pinned_with_hashes(tmp_path: Path) -> None:
    """S9.3 c2: the three executed runs pin the defect; hashes recompute."""

    from ayran.evidence.load import (
        load_hypothesis,
        load_nodes_by_type,
        load_verdicts_for,
        node_props,
    )
    from ayran.evidence.service import gate_b, poc_run
    from m6_fixtures import (
        MUTATED_SOURCE_BYTES,
        POC_SOURCE_BYTES,
        TRACE_OUTPUT_BYTES,
        open_store,
        recorded_poc_for_executed,
    )

    store = open_store(tmp_path)
    try:
        hid = _observed_hypothesis(store)
        poc = poc_run(store, hid, recorded=recorded_poc_for_executed(hid))
        result = gate_b(
            store,
            hid,
            obligations=GATE_B_EXECUTED,
            poc_id=str(poc["poc_id"]),
            caller={"kind": "model", "id": "prime:sess-r2"},
        )
        assert result["verdict"] == "defect_pinned"
        assert result["krait_stamp"] == KRAIT_PASS
        assert result["pinned"] is True
        record = result["record"]
        assert record["schema_version"] == "2.0.0"
        assert record["resulting_hypothesis_status"] == "defect_pinned"

        # Every executable obligation carries the full executed field set.
        executions = record["obligation_executions"]
        for name in (
            "clean_replay",
            "numerical_assertions",
            "negative_controls",
            "defect_removal",
            "fix_efficacy",
        ):
            assert name in executions, name
            block = executions[name]
            assert {
                "command",
                "argv",
                "cwd",
                "exit_code",
                "stdout_sha256",
                "duration_ms",
                "artifact_ids",
            } <= set(block), name
            assert block["stdout_sha256"].startswith("sha256:"), name

        # Hashes RECOMPUTED INSIDE the test against the record.
        by_kind = {entry["kind"]: entry["sha256"] for entry in record["artifact_hashes"]}
        assert by_kind["poc_source"] == "sha256:" + hashlib.sha256(POC_SOURCE_BYTES).hexdigest()
        assert by_kind["trace_output"] == "sha256:" + hashlib.sha256(TRACE_OUTPUT_BYTES).hexdigest()
        assert by_kind["mutated_source"] == "sha256:" + hashlib.sha256(MUTATED_SOURCE_BYTES).hexdigest()

        # Promotion happened: observed -> defect_pinned, records persisted.
        pinned = load_hypothesis(store, hid)
        assert pinned is not None and pinned["status"] == "defect_pinned"
        summaries = load_verdicts_for(store, hid)
        assert summaries and summaries[0]["schema_version"] == "1.0.0"
        assert summaries[0]["resulting_hypothesis_status"] == "defect_pinned"
        executions_nodes = load_nodes_by_type(store, "GateBExecutionRecord")
        assert executions_nodes
        props = node_props(executions_nodes[0])
        assert props["krait_stamp"] == KRAIT_PASS
        sealed = json.loads(str(props["record_json"]))
        assert sealed["krait_stamp"] == KRAIT_PASS
        assert sealed["verdict_id"] == summaries[0]["verdict_id"]
    finally:
        store.close()


def test_unpinned_cannot_advance_past_observed(tmp_path: Path) -> None:
    """[POC-UNPINNED]: reproduces but pinning incomplete -> stays observed."""

    from ayran.evidence.load import load_hypothesis, load_verdicts_for
    from ayran.evidence.service import gate_b
    from m6_fixtures import CONTROL_RUN_BLOCK, open_store

    store = open_store(tmp_path)
    try:
        hid = _observed_hypothesis(store)
        payload = dict(GATE_B_EXECUTED)
        no_coverage = {k: v for k, v in CONTROL_RUN_BLOCK.items() if k != "coverage"}
        payload["negative_controls"] = dict(no_coverage)
        payload["defect_removal"] = dict(no_coverage)
        result = gate_b(store, hid, obligations=payload)
        assert result["verdict"] == "needs_reformulation"
        assert result["krait_stamp"] == KRAIT_UNPINNED
        assert result["transition"] is None
        after = load_hypothesis(store, hid)
        assert after is not None and after["status"] == "observed"
        assert load_verdicts_for(store, hid)  # the attempt is still sealed
    finally:
        store.close()


def test_patch_touching_test_paths_forces_pre_execution_reformulation(tmp_path: Path) -> None:
    """E3: out-of-scope patch blocks BEFORE any run executes."""

    from ayran.evidence.service import gate_b
    from m6_fixtures import open_store

    class CountingRunner(ScriptedRunner):
        pass

    store = open_store(tmp_path)
    try:
        hid = _observed_hypothesis(store)
        runner = CountingRunner()
        payload = dict(GATE_B_EXECUTED)
        payload["patch"] = {"files": [{"path": "test/Exploit.t.sol", "content": "patched"}]}
        result = gate_b(store, hid, obligations=payload, runner=runner)
        assert result["verdict"] == "needs_reformulation"
        assert result["patch_scope_violations"]
        assert runner.executions == []  # nothing executed: pure pre-check
        assert "test/harness/config" in result["obligations"]["defect_removal"]["detail"]
    finally:
        store.close()


def test_judgment_obligations_recorded_verbatim_and_non_gating(tmp_path: Path) -> None:
    """Judgment blocks are recorded verbatim, never forgery, never gating."""

    from ayran.evidence.service import gate_b
    from m6_fixtures import open_store

    store = open_store(tmp_path)
    try:
        hid = _observed_hypothesis(store)
        payload = dict(GATE_B_EXECUTED)
        payload["alternate_paths"] = {"passed": True, "detail": "repeatable; fallback reenter unique"}
        payload["independent_skeptic"] = {"passed": True, "detail": "skeptic arrives with R3"}
        payload["deployment_identity"] = {"claimed": False, "detail": "repo-only"}
        result = gate_b(store, hid, obligations=payload)
        assert result["verdict"] == "defect_pinned"
        recorded = result["record"]["judgment_obligations"]
        assert recorded["alternate_paths"] == payload["alternate_paths"]
        assert recorded["deployment_identity"] == payload["deployment_identity"]
        # Omitted judgment obligations still do not gate (fresh hypothesis —
        # a pinned one can never re-enter Gate B).
        second = _observed_hypothesis(store, claim=_OBSERVED_CLAIM + " (judgment-omitted pass)")
        bare = gate_b(store, second, obligations=dict(GATE_B_EXECUTED))
        assert bare["verdict"] == "defect_pinned"
        assert "independent_skeptic" not in bare["record"]["judgment_obligations"]
    finally:
        store.close()


def test_governed_proof_refusal_path_unchanged(tmp_path: Path) -> None:
    """The contest-policy refusal keeps its exact historical shape."""

    from ayran.evidence.service import gate_b
    from m6_fixtures import GATE_B_PASS, open_store

    store = open_store(tmp_path)
    try:
        hid = _observed_hypothesis(store)
        result = gate_b(store, hid, obligations=dict(GATE_B_PASS), profile="governed_proof")
        assert result["schema_version"] == "1.0.0"
        assert result["verdict"] == "needs_reformulation"
        assert result["label"] == "proof_based"
        assert result["record"] is None
        assert result["reason"] == (
            "governed_proof requires contest policy to allow non-executable qualification"
        )
    finally:
        store.close()


def test_v1_gate_b_records_remain_readable(tmp_path: Path) -> None:
    """E5: historical 1.0.0 verdict records still parse; forward-only."""

    from ayran.evidence.load import load_verdict, load_verdicts_for
    from ayran.evidence.persist import persist_contract
    from ayran.evidence.service import gate_b
    from ayran.gates.gate_b import build_verdict_record
    from m6_fixtures import GATE_B_PASS, open_store

    store = open_store(tmp_path)
    try:
        hid = _observed_hypothesis(store)
        legacy = build_verdict_record(
            hypothesis={
                "hypothesis_id": hid,
                "run_id": "run_01J00000000000000000000001",
                "created_at": "2026-08-12T12:00:00Z",
                "target_identity": {
                    "target_id": "tgt_01J00000000000000000000001",
                    "source_tree_hash": "sha256:" + "d" * 64,
                    "scope_id": "scp_01J00000000000000000000001",
                    "commit": "1" * 40,
                },
            },
            verdict="defect_pinned",
            results={
                name: {"passed": True, "detail": "historical"}
                for name in GATE_B_PASS
                if isinstance(GATE_B_PASS[name], dict)
            },
            created_at="2026-08-12T12:00:00Z",
            evidence_ids=[],
            profile="executable",
        )
        persist_contract(store, "da-verdict", legacy, actor={"kind": "gate", "id": "ayran.gate_b", "version": "1.0.0"}, event_stem="da_verdict")
        found = load_verdict(store, str(legacy["verdict_id"]))
        assert found is not None and found["schema_version"] == "1.0.0"
        # A subsequent v2 run coexists; old records are never rewritten.
        modern = gate_b(store, hid, obligations=GATE_B_EXECUTED)
        assert modern["record"]["schema_version"] == "2.0.0"
        still = load_verdict(store, str(legacy["verdict_id"]))
        assert still is not None and still["schema_version"] == "1.0.0"
        assert len(load_verdicts_for(store, hid)) == 2
    finally:
        store.close()


def test_forgery_via_rpc_names_channel_derived_caller(tmp_path: Path) -> None:
    """E2 at the RPC boundary: the journal names the channel-derived identity."""

    from ayran.evidence.load import load_nodes_by_type, node_props
    from test_r1_hypothesis_remember import _sidecar

    dispatcher, store = _sidecar(tmp_path / "rpc")
    try:
        hid = _observed_hypothesis(store)
        denial = dispatcher.dispatch(
            "evidence.gate_b",
            {
                "hypothesis_id": hid,
                "obligations": {"clean_replay": {"passed": True}},
                "session": "sess-r2",
            },
        )
        assert denial["verdict"] == "needs_reformulation"
        assert denial["forgery_rejected"] is True
        events = [
            node_props(node)
            for node in load_nodes_by_type(store, "SessionTransition")
            if node_props(node).get("event_type") == "obligation_forgery_rejected"
        ]
        assert events
        assert "prime:sess-r2" in str(events[0].get("payload_json"))
    finally:
        store.close()
