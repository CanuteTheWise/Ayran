"""M6 finding builder, renderer, and linter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from ayran.api.validators import validate_contract
from ayran.context.ids import content_id
from ayran.evidence.actors import ACTOR_EVIDENCE
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
from ayran.reporting.linter import lint
from m5_fixtures import VAULT_SOURCE
from m6_fixtures import (
    CHALLENGER_SUBMISSION_POC_WORTHY,
    GATE_B_EXECUTED,
    REENTRANT_SOURCE,
    TRUE_DEFECT_EVIDENCE,
    challenger_gate_a,
    open_store,
    promote_supported,
    recorded_poc_for_executed,
    seed_hypothesis,
)


def _pipeline(store: GraphStore) -> dict[str, str]:
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
    assert a["verdict"] == "poc_worthy"
    poc = poc_run(
        store,
        hid,
        recorded=recorded_poc_for_executed(hid),
    )
    assert poc["status"] == "succeeded"
    b = gate_b(store, hid, obligations=GATE_B_EXECUTED, poc_id=str(poc["poc_id"]))
    assert b["verdict"] == "defect_pinned"
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
        actor=ACTOR_EVIDENCE,
        cause="independent review complete",
    )
    finding = finding_build(store, hid)
    return {
        "hypothesis_id": hid,
        "finding_id": str(finding["finding_id"]),
        "gate_a": str(a["verdict_id"]),
        "gate_b": str(b["verdict_id"]),
    }


def test_finding_builder_schema_and_required_fields(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        ids = _pipeline(store)
        from ayran.evidence.load import load_finding

        finding = load_finding(store, ids["finding_id"])
        assert finding is not None
        validate_contract("finding", finding)
        assert finding["status"] == "validated"
        assert finding["gate_a_verdict_id"] == ids["gate_a"]
        assert finding["gate_b_verdict_id"] == ids["gate_b"]
        assert finding["severity"]["rule_citation"]
        assert finding["impact"]["assumptions"]
    finally:
        store.close()


def test_renderer_tags_claims_and_labels_assumptions(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        ids = _pipeline(store)
        rendered = report_render(store, ids["finding_id"], fmt="markdown")
        body = str(rendered["body"])
        assert "[evidence:" in body
        assert "[assumption:" in body
        json_rendered = report_render(store, ids["finding_id"], fmt="json")
        assert '"finding_id"' in str(json_rendered["body"])
        linted = report_lint(store, ids["finding_id"], current_source=REENTRANT_SOURCE)
        assert linted["passed"] is True
        assert linted["hard"] == []
    finally:
        store.close()


def test_linter_rejects_missing_proof_language_secrets_and_stale(tmp_path: Path) -> None:
    finding: dict[str, Any] = {
        "status": "candidate",
        "affected_code": ["ReentrantVault.sol:9999"],
        "reproduction_artifact_id": None,
        "severity": {},
        "evidence_ids": [],
        "finding_id": "fnd_01J00000000000000000000001",
    }
    markdown = (
        "This is exploitable. The attacker steals funds. Path F:\\secrets\\key.pem was used. "
        "withdraw is broken."
    )
    result = lint(finding, markdown, current_source=REENTRANT_SOURCE)
    assert result["passed"] is False
    assert "status below validated" in result["hard"]
    assert "missing proof" in result["hard"]
    assert "unsupported definitive language" in result["hard"]
    assert "secret/path leakage" in result["hard"]
    assert "stale source lines" in result["hard"]


def test_report_generation_launches_no_tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []

    def _boom(*_args: object, **_kwargs: object) -> None:
        called.append("tool")
        raise AssertionError("report generation must not launch tools")

    monkeypatch.setattr("ayran.tools.runner.run_capability", _boom)
    store = open_store(tmp_path)
    try:
        ids = _pipeline(store)
        report_render(store, ids["finding_id"])
        report_lint(store, ids["finding_id"], current_source=VAULT_SOURCE)
        assert called == []
    finally:
        store.close()
