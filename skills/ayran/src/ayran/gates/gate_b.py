"""Gate B — post-PoC causal falsification. No model calls."""

from __future__ import annotations

from typing import Any

from ayran.context.contracts import provenance_record, seal
from ayran.context.ids import content_id
from ayran.evidence.actors import ACTOR_GATE_B
from ayran.evidence.errors import EVIDENCE_CEILING, GATE_PRECONDITION, EvidenceError
from ayran.evidence.types import (
    DECISION_TO_SCHEMA,
    GATE_B_DECISIONS,
    GATE_B_OBLIGATIONS,
    RULE_VERSION,
    SOURCE_URI,
)


def _flag(block: dict[str, Any] | None, key: str = "passed") -> bool:
    if not isinstance(block, dict):
        return False
    return block.get(key) is True


def evaluate_obligations(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for name in GATE_B_OBLIGATIONS:
        block = payload.get(name)
        if not isinstance(block, dict):
            results[name] = {
                "passed": False,
                "detail": "unspecified",
                "unspecified": True,
            }
            continue
        passed = block.get("passed")
        wrong_reason = block.get("wrong_reason") is True
        results[name] = {
            "passed": passed is True and not wrong_reason,
            "detail": str(block.get("detail") or ("passed" if passed else "failed"))[:2048],
            "unspecified": False,
            "wrong_reason": wrong_reason,
            "feature_disabled": block.get("feature_disabled") is True,
            "exploit_persists": block.get("exploit_persists") is True,
        }
    return results


def decide_verdict(results: dict[str, dict[str, Any]], *, profile: str) -> str:
    if profile == "governed_proof":
        required = (
            "numerical_assertions",
            "defect_removal",
            "fix_efficacy",
            "independent_skeptic",
            "feasibility_scope_severity",
        )
        # Non-executable: clean replay may be waived only under governed_proof.
        missing_proof = [name for name in required if not _flag(results.get(name))]
        if missing_proof:
            return "needs_reformulation"
        return "defect_pinned"

    unspecified = [name for name, item in results.items() if item.get("unspecified")]
    if unspecified:
        return "needs_reformulation"
    if any(item.get("wrong_reason") for item in results.values()):
        return "needs_reformulation"
    removal = results.get("defect_removal") or {}
    if removal.get("exploit_persists"):
        return "needs_reformulation"
    efficacy = results.get("fix_efficacy") or {}
    if efficacy.get("feature_disabled"):
        return "needs_reformulation"
    if not _flag(results.get("clean_replay")):
        return "needs_reformulation"
    if not _flag(results.get("numerical_assertions")):
        return "needs_reformulation"
    if not _flag(results.get("negative_controls")):
        return "needs_reformulation"
    if not _flag(results.get("defect_removal")) or not _flag(results.get("fix_efficacy")):
        return "needs_reformulation"
    if not _flag(results.get("alternate_paths")):
        return "needs_reformulation"
    if not _flag(results.get("independent_skeptic")):
        return "needs_reformulation"
    # Deployment identity is required only when claimed.
    identity = results.get("deployment_identity") or {}
    if identity.get("claimed") and not _flag(identity):
        return "needs_reformulation"
    if not _flag(results.get("feasibility_scope_severity")):
        return "needs_reformulation"
    if any(item.get("falsified") for item in results.values()):
        return "falsified"
    replay = results.get("clean_replay") or {}
    if replay.get("mismatch"):
        return "falsified"
    return "defect_pinned"


def build_verdict_record(
    *,
    hypothesis: dict[str, Any],
    verdict: str,
    results: dict[str, dict[str, Any]],
    created_at: str,
    evidence_ids: list[str],
    profile: str,
) -> dict[str, Any]:
    hypothesis_id = str(hypothesis["hypothesis_id"])
    verdict_id = content_id("dav", "gate-b", hypothesis_id, verdict, profile)
    attempts = [
        {
            "question": name,
            "result": str(item.get("detail") or ("pass" if item.get("passed") else "fail"))[:2048],
            "evidence_ids": evidence_ids[:256],
            "untried_dimensions": [] if item.get("passed") else [name],
        }
        for name, item in results.items()
    ]
    if not attempts:
        attempts = [
            {
                "question": "Gate B obligations",
                "result": "no obligations supplied",
                "evidence_ids": [],
                "untried_dimensions": list(GATE_B_OBLIGATIONS),
            }
        ]
    record: dict[str, Any] = {
        "schema_version": "1.0.0",
        "verdict_id": verdict_id,
        "created_at": created_at,
        "run_id": hypothesis["run_id"],
        "target_identity": dict(hypothesis["target_identity"]),
        "gate": "B",
        "decision": DECISION_TO_SCHEMA[verdict],
        "resulting_hypothesis_status": verdict,
        "hypothesis_id": hypothesis_id,
        "evidence_ids": evidence_ids[:256],
        "falsification_attempts": attempts[:64],
        "causal_chain": [
            f"{name}:{'pass' if item.get('passed') else 'fail'}"[:1024] for name, item in results.items()
        ][:64]
        or ["gate-b:no-obligations"],
        "dissent": [
            f"{name}:{item.get('detail')}"[:1024]
            for name, item in results.items()
            if not item.get("passed")
        ][:32],
        "confidence": 1.0 if verdict == "defect_pinned" else 0.5,
        "deterministic_rule_version": RULE_VERSION,
        "reviewer": dict(ACTOR_GATE_B),
        "independent_from": [hypothesis_id],
        "provenance": [
            provenance_record(created_at=created_at, source_uri=SOURCE_URI, material=verdict_id)
        ],
    }
    return seal(record)


def run_gate_b(
    hypothesis: dict[str, Any],
    *,
    obligations: dict[str, Any] | None = None,
    poc: dict[str, Any] | None = None,
    created_at: str | None = None,
    profile: str = "executable",
) -> dict[str, Any]:
    status = str(hypothesis.get("status") or "lead")
    grade = str(hypothesis.get("evidence_grade") or "lead")
    if status != "observed":
        raise EvidenceError(
            GATE_PRECONDITION,
            f"Gate B requires an observed hypothesis, not {status}",
            details={"status": status},
        )
    if grade == "lead":
        raise EvidenceError(
            EVIDENCE_CEILING,
            "Gate B refuses lead-grade evidence; only observed tool evidence may feed Gate B",
            details={"evidence_grade": grade},
        )
    payload = dict(obligations or {})
    if poc and not payload.get("clean_replay"):
        replay_ok = str(poc.get("replay_hash") or "") == str(poc.get("result_hash") or "")
        if poc.get("replay_matched") is True:
            replay_ok = True
        payload["clean_replay"] = {
            "passed": replay_ok and str(poc.get("status") or "") == "succeeded",
            "detail": "replay hash compared to original ToolRun",
            "mismatch": bool(poc.get("replay_hash") and not replay_ok),
        }
    if profile not in {"executable", "governed_proof"}:
        profile = "executable"
    if profile == "governed_proof" and not payload.get("contest_policy_allows_proof"):
        return {
            "schema_version": "1.0.0",
            "verdict": "needs_reformulation",
            "profile": profile,
            "label": "proof_based",
            "obligations": evaluate_obligations(payload),
            "record": None,
            "reason": "governed_proof requires contest policy to allow non-executable qualification",
        }
    results = evaluate_obligations(payload)
    verdict = decide_verdict(results, profile=profile)
    if verdict not in GATE_B_DECISIONS:
        verdict = "needs_reformulation"
    evidence_ids = [
        str(item)
        for item in (payload.get("evidence_ids") or (poc or {}).get("evidence_ids") or [])
        if isinstance(item, str)
    ]
    stamp = created_at or str(hypothesis.get("created_at") or "")
    record = build_verdict_record(
        hypothesis=hypothesis,
        verdict=verdict,
        results=results,
        created_at=stamp,
        evidence_ids=evidence_ids,
        profile=profile,
    )
    return {
        "schema_version": "1.0.0",
        "verdict": verdict,
        "profile": profile,
        "label": "proof_based" if profile == "governed_proof" else "executable",
        "obligations": results,
        "record": record,
        "experiment_revision_required": any(
            item.get("wrong_reason") or item.get("exploit_persists") for item in results.values()
        ),
    }
