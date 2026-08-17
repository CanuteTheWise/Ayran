"""Canonical Finding builder validated against finding.schema.json."""

from __future__ import annotations

from typing import Any

from ayran.api.validators import validate_contract
from ayran.context.contracts import provenance_record, seal
from ayran.context.ids import content_id
from ayran.evidence.types import (
    DEFAULT_SCOPE_ID,
    DEFAULT_SEVERITY_POLICY_ID,
    SOURCE_URI,
    as_mapping,
)


def _title(hypothesis: dict[str, Any]) -> str:
    claim = str(hypothesis.get("claim") or "Untitled defect")
    return claim[:256]


def build_finding(
    hypothesis: dict[str, Any],
    *,
    impact: dict[str, Any],
    severity: dict[str, Any] | None = None,
    dedup: dict[str, Any] | None = None,
    gate_a_id: str | None = None,
    gate_b_id: str | None = None,
    poc: dict[str, Any] | None = None,
    created_at: str | None = None,
    validated: bool = False,
) -> dict[str, Any]:
    stamp = created_at or str(hypothesis.get("created_at") or "")
    finding_id = content_id("fnd", str(hypothesis.get("hypothesis_id") or ""), str(hypothesis.get("status") or ""))
    raw_impact = impact.get("finding_impact")
    finding_impact: dict[str, Any] = (
        dict(raw_impact)
        if isinstance(raw_impact, dict)
        else {
            "kind": "integrity",
            "equation": "attacker_net = unspecified",
            "lower_bound": "0",
            "upper_bound": None,
            "assumptions": ["no numerical impact supplied"],
        }
    )
    evidence_ids = [
        str(item)
        for item in (
            list((poc or {}).get("evidence_ids") or [])
            + ([gate_a_id] if gate_a_id else [])
            + ([gate_b_id] if gate_b_id else [])
        )
        if item
    ]
    if not evidence_ids:
        evidence_ids = [content_id("evd", finding_id, "placeholder")]
    # Unique, schema-bounded.
    unique: list[str] = []
    for item in evidence_ids:
        if item not in unique:
            unique.append(item)
    evidence_ids = unique[:256]
    affected = [str(item)[:512] for item in (hypothesis.get("attack_path") or ["target/src:1"])][:64]
    if poc and poc.get("source_span"):
        affected = [str(poc["source_span"])[:512], *affected]
    preconditions = []
    for item in hypothesis.get("preconditions") or []:
        if isinstance(item, dict):
            preconditions.append(str(item.get("description") or "precondition")[:1024])
        else:
            preconditions.append(str(item)[:1024])
    if not preconditions:
        preconditions = ["unprivileged caller"]
    record: dict[str, Any] = {
        "schema_version": "1.0.0",
        "finding_id": finding_id,
        "created_at": stamp,
        "run_id": hypothesis["run_id"],
        "target_identity": dict(hypothesis["target_identity"]),
        "status": "validated" if validated else "candidate",
        "title": _title(hypothesis),
        "root_cause": str(hypothesis.get("root_cause") or hypothesis.get("claim") or "unspecified")[:4096],
        "violated_invariant": str(
            (hypothesis.get("invariant_ids") or ["unspecified invariant"])[0]
            if hypothesis.get("invariant_ids")
            else hypothesis.get("claim") or "unspecified invariant"
        )[:2048],
        "affected_code": affected[:64] or ["target/src/Contract.sol:1"],
        "attacker_model": str(
            as_mapping(impact.get("attacker_model")).get("reachability") or "unprivileged attacker"
        )[:4096],
        "preconditions": preconditions[:64],
        "impact": {
            "kind": finding_impact["kind"],
            "equation": str(finding_impact["equation"])[:2048],
            "lower_bound": str(finding_impact["lower_bound"])[:128],
            "upper_bound": finding_impact.get("upper_bound"),
            "assumptions": [str(item)[:1024] for item in (finding_impact.get("assumptions") or [])][:64],
        },
        "evidence_ids": evidence_ids,
        "trust_class": "runtime_observation" if validated else str(hypothesis.get("trust_class") or "model_observation"),
        "confidence": 1.0 if validated else 0.7,
        "provenance": [
            provenance_record(created_at=stamp, source_uri=SOURCE_URI, material=finding_id)
        ],
    }
    if validated:
        if not gate_a_id or not gate_b_id:
            raise ValueError("validated findings require Gate A and Gate B verdict ids")
        disposition = {
            "status": str((dedup or {}).get("status") or "unique"),
            "comparison": str((dedup or {}).get("comparisons", [{}])[0].get("comparison") if (dedup or {}).get("comparisons") else (dedup or {}).get("status") or "unique")[:2048],
            "source_refs": [],
        }
        if disposition["status"] not in {"unique", "variant", "duplicate_known_issue"}:
            disposition["status"] = "unique"
        sev = (severity or {}).get("finding_severity") or {}
        record.update(
            {
                "gate_a_verdict_id": gate_a_id,
                "gate_b_verdict_id": gate_b_id,
                "reproduction_artifact_id": str((poc or {}).get("tool_run_id") or evidence_ids[0]),
                "negative_control_ids": list((poc or {}).get("negative_control_ids") or [evidence_ids[0]])[:64],
                "defect_fix_evidence_ids": list((poc or {}).get("fix_evidence_ids") or [evidence_ids[0]])[:64],
                "scope_manifest_id": str(
                    hypothesis.get("target_identity", {}).get("scope_id") or DEFAULT_SCOPE_ID
                ),
                "duplicate_disposition": disposition,
                "severity": {
                    "label": str(sev.get("label") or "informational"),
                    "policy_id": str(sev.get("policy_id") or DEFAULT_SEVERITY_POLICY_ID),
                    "rule_citation": str(sev.get("rule_citation") or "policy unspecified")[:1024],
                },
                "uncertainty": list((severity or {}).get("ambiguities") or impact.get("assumptions") or [])[:64],
                "mitigations": [
                    str(item)[:2048]
                    for item in ((poc or {}).get("mitigations") or ["restore checks-effects-interactions"])
                ][:64]
                or ["restore checks-effects-interactions"],
            }
        )
        if not record["negative_control_ids"]:
            record["negative_control_ids"] = [evidence_ids[0]]
        if not record["defect_fix_evidence_ids"]:
            record["defect_fix_evidence_ids"] = [evidence_ids[0]]
        if not record["mitigations"]:
            record["mitigations"] = ["restore checks-effects-interactions"]
        if record["severity"]["label"] not in {"informational", "low", "medium", "high", "critical"}:
            record["severity"]["label"] = "informational"
    sealed = seal(record)
    validate_contract("finding", sealed)
    extras = {
        "hypothesis_id": str(hypothesis.get("hypothesis_id") or ""),
        "attack_steps": list(hypothesis.get("attack_path") or []),
        "one_command": str((poc or {}).get("one_command") or ""),
        "expected_output": str((poc or {}).get("stdout_excerpt") or ""),
        "result_hash": str((poc or {}).get("result_hash") or ""),
        "report_render_version": "1.0.0",
    }
    return {**sealed, "_extras": extras}
