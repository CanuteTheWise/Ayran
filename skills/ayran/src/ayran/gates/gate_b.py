"""Gate B — post-PoC causal falsification. No model calls.

R2 (spec §5.6, S9.3, INV-5.6/5.7/5.10): the executable profile decides every
obligation from EXECUTED artifacts through :mod:`ayran.gates.gate_b_mechanical`
— three real runs (vulnerable replay, patched control, revert-mutation), each
hashed over a canonicalized assertion summary. The boolean-honor path is
deleted: a bare ``{"passed": true}`` raises ``OBLIGATION_FORGERY_REJECTED``
at parse time (S9.3 c1), and any executable block lacking ``command`` +
``exit_code`` forces ``needs_reformulation``.

The ``governed_proof`` profile and its contest-policy gate survive unchanged
in meaning: proof-based qualification stays flag-evaluated only under an
explicit contest policy that allows non-executable qualification.
"""

from __future__ import annotations

from typing import Any

from ayran.context.contracts import provenance_record, seal
from ayran.context.ids import content_id
from ayran.evidence.actors import ACTOR_GATE_B
from ayran.evidence.errors import (
    EVIDENCE_CEILING,
    GATE_PRECONDITION,
    OBLIGATION_FORGERY_REJECTED,
    EvidenceError,
)
from ayran.evidence.types import (
    DECISION_TO_SCHEMA,
    GATE_B_DECISIONS,
    GATE_B_OBLIGATIONS,
    RULE_VERSION,
    SOURCE_URI,
)
from ayran.gates.gate_b_mechanical import (
    DEFAULT_MATCH_TEST,
    JUDGMENT_OBLIGATIONS,
    KRAIT_UNPINNED,
    MechanicalRunner,
    ScriptedRunner,
    artifact_hashes,
    classify_runs,
    detect_forgery,
    execute_runs,
    patch_scope_violations,
)


def _flag(block: dict[str, Any] | None, key: str = "passed") -> bool:
    if not isinstance(block, dict):
        return False
    return block.get(key) is True


def evaluate_obligations(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Governed-proof obligation flag evaluation (non-executable profile only).

    The executable profile NEVER consults these flags — its obligations are
    decided mechanically from executed runs in ``gate_b_mechanical``.
    """

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
    # The executable honor ladder is deleted (§5.6); executable verdicts are
    # derived mechanically by gate_b_mechanical.classify_runs.
    raise EvidenceError(
        GATE_PRECONDITION,
        "decide_verdict evaluates only the governed_proof profile; "
        "executable verdicts come from executed artifacts",
    )


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


def build_v2_verdict_record(
    *,
    hypothesis: dict[str, Any],
    verdict: str,
    results: dict[str, dict[str, Any]],
    classification: Any,
    created_at: str,
    evidence_ids: list[str],
    profile: str,
    artifact_hash_entries: list[dict[str, str]],
    judgment_payloads: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Schema v2 verdict record: everything v1 carried, plus the Krait stamp,
    recomputable artifact hashes, per-obligation executed blocks, and judgment
    obligations recorded verbatim (never gating, §5.6 schema additions)."""

    summary = build_verdict_record(
        hypothesis=hypothesis,
        verdict=verdict,
        results=results,
        created_at=created_at,
        evidence_ids=evidence_ids,
        profile=profile,
    )
    record = dict(summary)
    record["schema_version"] = "2.0.0"
    record["krait_stamp"] = classification.krait_stamp
    record["artifact_hashes"] = artifact_hash_entries
    record["obligation_executions"] = dict(classification.executed_blocks)
    record["judgment_obligations"] = {
        name: dict(block) for name, block in judgment_payloads.items() if isinstance(block, dict)
    }
    record["pinning"] = {
        "pinned": bool(classification.pinned),
        "replay_reproduced": bool(classification.replay_reproduced),
        "reasons": list(classification.reasons)[:32],
    }
    return seal(record)


def _governed_refusal(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "verdict": "needs_reformulation",
        "profile": profile,
        "label": "proof_based",
        "obligations": evaluate_obligations(payload),
        "record": None,
        "reason": "governed_proof requires contest policy to allow non-executable qualification",
    }


def _expected_replay_hash(payload: dict[str, Any], poc: dict[str, Any] | None) -> str | None:
    block = payload.get("clean_replay")
    if isinstance(block, dict) and isinstance(block.get("expected_replay_hash"), str):
        return str(block["expected_replay_hash"])
    if isinstance(poc, dict):
        candidate = str(poc.get("replay_hash") or "")
        if candidate.startswith("sha256:"):
            return candidate
    return None


def run_gate_b(
    hypothesis: dict[str, Any],
    *,
    obligations: dict[str, Any] | None = None,
    poc: dict[str, Any] | None = None,
    created_at: str | None = None,
    profile: str = "executable",
    runner: MechanicalRunner | None = None,
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
    if profile not in {"executable", "governed_proof"}:
        profile = "executable"
    if profile == "governed_proof":
        # Proof-based qualification survives with its meaning unchanged: the
        # contest-policy gate decides before any obligation is evaluated.
        if not payload.get("contest_policy_allows_proof"):
            return _governed_refusal(profile, payload)
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
            "label": "proof_based",
            "obligations": results,
            "record": record,
            "projection_record": record,
            "experiment_revision_required": any(
                item.get("wrong_reason") or item.get("exploit_persists") for item in results.values()
            ),
        }

    # --- executable profile: executed artifacts only (S9.3, INV-5.6) --------
    forged = detect_forgery(payload)
    if forged:
        raise EvidenceError(
            OBLIGATION_FORGERY_REJECTED,
            "obligation(s) "
            + ", ".join(forged)
            + " assert a bare pass with no executed run; booleans are not artifacts",
            details={"obligations": forged},
        )
    stamp = created_at or str(hypothesis.get("created_at") or "")
    patch_violations = patch_scope_violations(payload)
    if patch_violations:
        # Mechanical pre-check BEFORE any execution: out-of-scope patches
        # force reformulation without a single run.
        results = {
            name: {"passed": False, "detail": "blocked pre-execution", "unspecified": True}
            for name in GATE_B_OBLIGATIONS
        }
        results["defect_removal"] = {
            "passed": False,
            "detail": "patch scope violation: " + "; ".join(patch_violations)[:2048],
            "unspecified": False,
        }
        evidence_ids = [
            str(item) for item in (payload.get("evidence_ids") or []) if isinstance(item, str)
        ]
        record = build_verdict_record(
            hypothesis=hypothesis,
            verdict="needs_reformulation",
            results=results,
            created_at=stamp,
            evidence_ids=evidence_ids,
            profile=profile,
        )
        return {
            "schema_version": "2.0.0",
            "verdict": "needs_reformulation",
            "profile": profile,
            "label": "executable",
            "obligations": results,
            "krait_stamp": None,
            "pinned": False,
            "artifact_hashes": [],
            "record": record,
            "projection_record": record,
            "patch_scope_violations": patch_violations,
            "experiment_revision_required": True,
        }

    used_runner = runner if runner is not None else ScriptedRunner()
    runs = execute_runs(payload, used_runner)
    classification = classify_runs(
        payload,
        runs,
        match_test=str(payload.get("match_test") or DEFAULT_MATCH_TEST),
        expected_replay_hash=_expected_replay_hash(payload, poc),
    )
    # Judgment obligations are recorded verbatim; they never gate pinning in
    # this milestone — the three executed runs decide (S9.3 c2; skeptic = R3).
    judgment_payloads: dict[str, dict[str, Any]] = {}
    for name in JUDGMENT_OBLIGATIONS:
        judgment_block = payload.get(name)
        if isinstance(judgment_block, dict):
            judgment_payloads[name] = judgment_block
    verdict = classification.verdict
    if verdict not in GATE_B_DECISIONS:
        verdict = "needs_reformulation"
    evidence_ids = [
        str(item)
        for item in (payload.get("evidence_ids") or (poc or {}).get("evidence_ids") or [])
        if isinstance(item, str)
    ]
    entries = artifact_hashes(payload)
    record = build_v2_verdict_record(
        hypothesis=hypothesis,
        verdict=verdict,
        results=classification.obligations,
        classification=classification,
        created_at=stamp,
        evidence_ids=evidence_ids,
        profile=profile,
        artifact_hash_entries=entries,
        judgment_payloads=judgment_payloads,
    )
    return {
        "schema_version": "2.0.0",
        "verdict": verdict,
        "profile": profile,
        "label": "executable",
        "obligations": classification.obligations,
        "krait_stamp": classification.krait_stamp,
        "pinned": classification.pinned,
        "artifact_hashes": entries,
        "record": record,
        "projection_record": build_verdict_record(
            hypothesis=hypothesis,
            verdict=verdict,
            results=classification.obligations,
            created_at=stamp,
            evidence_ids=evidence_ids,
            profile=profile,
        ),
        "transition_blocked_unpinned": classification.krait_stamp == KRAIT_UNPINNED,
        "experiment_revision_required": any(
            item.get("wrong_reason") or item.get("exploit_persists")
            for item in classification.obligations.values()
        ),
    }
