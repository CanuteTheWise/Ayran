"""M9 end-to-end scenarios from blueprint §19.7."""

from __future__ import annotations

from pathlib import Path

from ayran.context.ids import content_id
from ayran.evaluation.metrics import discover, false_positives
from ayran.evaluation.sealed import built_in_catalog
from ayran.evidence.service import (
    finding_build,
    gate_b,
    impact_assess,
    poc_run,
    report_lint,
    report_render,
    severity_assess,
    transition,
)
from ayran.graph.recovery import GraphStore
from m6_fixtures import (
    CHALLENGER_SUBMISSION_FALSIFIED,
    CHALLENGER_SUBMISSION_POC_WORTHY,
    GATE_B_PASS,
    REENTRANT_SOURCE,
    TRUE_DEFECT_EVIDENCE,
    challenger_gate_a,
    open_store,
    promote_supported,
    seed_hypothesis,
)


def _validated_finding(store: GraphStore) -> dict[str, str]:
    hyp = seed_hypothesis(
        store,
        claim="ReentrantVault.withdraw is reentrant because the external call happens before balances are zeroed",
        attack_path=["withdraw"],
        root_cause="reentrancy-call-before-zero",
        preconditions=["attacker contract with fallback"],
    )
    hid = str(hyp["hypothesis_id"])
    promote_supported(store, hid, TRUE_DEFECT_EVIDENCE)
    a = challenger_gate_a(store, hid, dict(CHALLENGER_SUBMISSION_POC_WORTHY))
    poc = poc_run(
        store,
        hid,
        recorded={
            "status": "succeeded",
            "stdout": "attacker_net=1000000000000000000",
            "result_hash": "sha256:" + "ab" * 32,
            "replay_hash": "sha256:" + "ab" * 32,
            "replay_matched": True,
            "one_command": "forge test --match-test test_exploit --json",
            "tool_run_id": content_id("trn", hid, "poc"),
            "evidence_ids": [content_id("evd", hid, "poc")],
            "negative_control_ids": [content_id("evd", hid, "neg")],
            "fix_evidence_ids": [content_id("evd", hid, "fix")],
        },
    )
    b = gate_b(store, hid, obligations=GATE_B_PASS, poc_id=str(poc["poc_id"]))
    impact = impact_assess(store, hid, assumptions={"unit_loss": "1", "repetitions": 1})
    severity = severity_assess(store, hid, impact=impact)
    transition(
        store,
        hid,
        "validated",
        evidence={
            "skeptic_id": content_id("act", "skeptic", hid),
            "scope_id": "scp_01J00000000000000000000001",
            "impact_id": impact["impact_id"],
            "dedup_id": content_id("clu", "dedup", hid),
            "severity_id": content_id("sev", hid, severity["label"]),
            "evidence_ids": [str(a["verdict_id"]), str(b["verdict_id"])],
        },
    )
    finding = finding_build(store, hid)
    rendered = report_render(store, finding["finding_id"], fmt="markdown")
    linted = report_lint(store, finding["finding_id"], current_source=REENTRANT_SOURCE)
    return {
        "hypothesis_id": hid,
        "finding_id": str(finding["finding_id"]),
        "gate_a": str(a["verdict"]),
        "gate_b": str(b["verdict"]),
        "lint_ok": str(bool(linted.get("passed"))),
        "report": str(rendered.get("body") or ""),
    }


def test_known_vulnerable_target_validates_and_lints(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        result = _validated_finding(store)
        assert result["gate_a"] == "poc_worthy"
        assert result["gate_b"] == "defect_pinned"
        assert result["finding_id"]
        assert result["lint_ok"] == "True"
    finally:
        store.close()


def test_clean_and_no_finding_scenarios_have_empty_ground_truth() -> None:
    catalog = {item.scenario: item for item in built_in_catalog()}
    assert catalog["clean_target"].ground_truth == []
    assert catalog["no_finding_report"].ground_truth == []
    assert discover("A7", catalog["clean_target"]) == []
    assert discover("A7", catalog["no_finding_report"]) == []


def test_false_positive_killed_at_gate_a(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        hyp = seed_hypothesis(
            store,
            claim="VulnerableVault.withdraw(uint256) sends eth to arbitrary user",
            attack_path=["withdraw"],
            root_cause="arbitrary-send-eth",
        )
        promote_supported(store, hyp["hypothesis_id"])
        result = challenger_gate_a(
            store, hyp["hypothesis_id"], dict(CHALLENGER_SUBMISSION_FALSIFIED)
        )
        assert result["verdict"] == "falsified"
    finally:
        store.close()


def test_duplicate_known_requires_global_graph() -> None:
    item = next(row for row in built_in_catalog() if row.scenario == "duplicate_known")
    assert discover("A3", item) == []
    assert discover("A4", item) == [] or discover("A5", item)


def test_flaky_poc_needs_gate_b() -> None:
    item = next(row for row in built_in_catalog() if row.scenario == "flaky_poc")
    assert false_positives("A2", item)
    assert discover("A2", item) == []
    assert discover("A5", item)


def test_optional_and_required_tool_failures() -> None:
    optional = next(row for row in built_in_catalog() if row.scenario == "unavailable_optional_tool")
    required = next(row for row in built_in_catalog() if row.scenario == "required_tool_failure")
    assert optional.optional_tool == "adapter.slither"
    assert required.required_tool == "adapter.foundry"
    assert discover("A2", required) == []


def test_resume_after_crash_fixture_is_recoverable() -> None:
    item = next(row for row in built_in_catalog() if row.scenario == "resume_after_crash")
    assert item.resume is True
    assert discover("A5", item)
