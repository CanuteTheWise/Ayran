"""Gate A — knowledge-blind pre-PoC challenge. Sidecar clerk role (§5.5).

The deterministic regex decider (including the keyword verdict scorer and its
``poc_worthy`` fall-through), the caller-override verdict channel that once
lived in this module, and the legacy best-effort knowledge stripping are
DELETED: verdicts enter only as structurally validated submissions from the
independent challenger. This module validates structure and seals records; it
never spawns agents, never calls a model, and never synthesizes or substitutes
a verdict.
"""

from __future__ import annotations

from typing import Any

from ayran.context.contracts import provenance_record, seal
from ayran.context.ids import ZERO_HASH, content_id
from ayran.evidence.errors import (
    EVIDENCE_CEILING,
    GATE_PRECONDITION,
    SUBMISSION_INVALID,
    VERDICT_OVERRIDE_FORBIDDEN,
    EvidenceError,
)
from ayran.evidence.types import (
    DECISION_TO_SCHEMA,
    GATE_A_DECISIONS,
    PRECONDITION_DIMENSIONS,
    RULE_VERSION,
    SOURCE_URI,
)

INVARIANT_MIN_CHARS = 12
CHALLENGER_EXPERIMENT_FIELDS = ("inputs", "expected_positive", "expected_negative", "capability")


def _decision_status(verdict: str) -> tuple[str, str]:
    schema = DECISION_TO_SCHEMA[verdict]
    return schema, verdict


def validate_submission(submission: dict[str, Any]) -> dict[str, Any]:
    """Structural completeness validation of one challenger output (§5.5).

    Schema conformance, verdict enum membership, non-empty fields, and the
    invariant specificity floor: a ``violated_invariant`` shorter than
    :data:`INVARIANT_MIN_CHARS` characters structurally forces
    ``needs_reformulation``. This is a floor rule, not verdict synthesis.
    """

    if not isinstance(submission, dict):
        raise EvidenceError(SUBMISSION_INVALID, "the challenger submission must be an object")
    verdict = str(submission.get("verdict") or "")
    if verdict not in GATE_A_DECISIONS:
        raise EvidenceError(
            SUBMISSION_INVALID,
            f"verdict {verdict!r} is not one of {list(GATE_A_DECISIONS)}",
        )
    invariant = str(submission.get("violated_invariant") or "").strip()
    if not invariant:
        raise EvidenceError(SUBMISSION_INVALID, "violated_invariant must be non-empty")
    benign = str(submission.get("strongest_benign_explanation") or "").strip()
    if not benign:
        raise EvidenceError(
            SUBMISSION_INVALID, "strongest_benign_explanation must be non-empty"
        )
    experiment = submission.get("cheapest_decisive_experiment")
    if not isinstance(experiment, dict):
        raise EvidenceError(
            SUBMISSION_INVALID, "cheapest_decisive_experiment must be an object"
        )
    for field in CHALLENGER_EXPERIMENT_FIELDS:
        value = experiment.get(field)
        empty = value is None or (
            isinstance(value, str) and not value.strip()
        ) or (
            isinstance(value, (list, tuple, dict)) and not value
        )
        if empty:
            raise EvidenceError(
                SUBMISSION_INVALID,
                f"cheapest_decisive_experiment.{field} must be non-empty",
            )
    raw_preconditions = submission.get("preconditions")
    if not isinstance(raw_preconditions, list) or not raw_preconditions:
        raise EvidenceError(SUBMISSION_INVALID, "preconditions must be a non-empty list")
    preconditions: list[dict[str, Any]] = []
    for raw in raw_preconditions[:64]:
        if not isinstance(raw, dict):
            raise EvidenceError(
                SUBMISSION_INVALID, "each challenger precondition must be an object"
            )
        dimension = str(raw.get("dimension") or "").strip()
        detail = str(raw.get("detail") or "").strip()
        if not dimension or not detail:
            raise EvidenceError(
                SUBMISSION_INVALID,
                "each challenger precondition needs non-empty dimension and detail",
            )
        if not isinstance(raw.get("present"), bool):
            raise EvidenceError(SUBMISSION_INVALID, "precondition.present must be boolean")
        can_create = raw.get("attacker_can_create")
        if can_create is not None and not isinstance(can_create, bool):
            raise EvidenceError(
                SUBMISSION_INVALID, "precondition.attacker_can_create must be boolean or null"
            )
        preconditions.append(
            {
                "dimension": dimension[:256],
                "present": bool(raw["present"]),
                "attacker_can_create": can_create,
                "detail": detail[:1024],
            }
        )
    if len(invariant) < INVARIANT_MIN_CHARS:
        verdict = "needs_reformulation"
    return {
        "verdict": verdict,
        "violated_invariant": invariant[:2048],
        "preconditions": preconditions,
        "strongest_benign_explanation": benign[:2048],
        "cheapest_decisive_experiment": {
            "inputs": [str(item)[:512] for item in (experiment.get("inputs") or [])[:32]]
            or ["unspecified input"],
            "expected_positive": str(experiment.get("expected_positive"))[:2048],
            "expected_negative": str(experiment.get("expected_negative"))[:2048],
            "capability": str(experiment.get("capability"))[:256],
        },
    }


def build_verdict_record(
    *,
    hypothesis: dict[str, Any],
    verdict: str,
    invariant: dict[str, Any],
    preconditions: list[dict[str, Any]],
    benign: str,
    facts: list[str],
    experiment: dict[str, Any],
    killed: list[str],
    untried: list[str],
    created_at: str,
    independent_from: list[str],
    reviewer: dict[str, Any],
    transcript_hash: str | None = None,
) -> dict[str, Any]:
    hypothesis_id = str(hypothesis["hypothesis_id"])
    verdict_id = content_id("dav", "gate-a", hypothesis_id, verdict, invariant["statement"])
    schema_decision, status = _decision_status(verdict)
    attempts = [
        {
            "question": "Is the claimed invariant exact and attacker-reachable?",
            "result": invariant["statement"][:2048],
            "evidence_ids": [],
            "untried_dimensions": untried[:64],
        },
        {
            "question": "What is the strongest benign explanation?",
            "result": benign[:2048],
            "evidence_ids": [],
            "untried_dimensions": untried[:64],
        },
        {
            "question": "Can an unprivileged attacker create every precondition?",
            "result": "; ".join(
                f"{item['dimension']}={'yes' if item.get('attacker_can_create') else 'no'}"
                for item in preconditions[:16]
            )[:2048]
            or "no preconditions enumerated",
            "evidence_ids": [],
            "untried_dimensions": untried[:64],
        },
    ]
    if facts:
        attempts.append(
            {
                "question": "Which missing source or deployment fact would resolve ambiguity?",
                "result": "; ".join(facts)[:2048],
                "evidence_ids": [],
                "untried_dimensions": untried[:64],
            }
        )
    raw_hash = (
        transcript_hash
        if isinstance(transcript_hash, str) and transcript_hash.startswith("sha256:")
        else ZERO_HASH
    )
    record: dict[str, Any] = {
        "schema_version": "1.0.0",
        "verdict_id": verdict_id,
        "created_at": created_at,
        "run_id": hypothesis["run_id"],
        "target_identity": dict(hypothesis["target_identity"]),
        "gate": "A",
        "decision": schema_decision,
        "resulting_hypothesis_status": status,
        "hypothesis_id": hypothesis_id,
        "evidence_ids": [],
        "falsification_attempts": attempts[:64],
        "causal_chain": [
            invariant["statement"][:1024],
            f"benign:{benign}"[:1024],
            f"experiment:{experiment.get('capability')}:{experiment.get('expected_positive')}"[:1024],
        ],
        "dissent": [f"killed:{item}"[:1024] for item in killed[:32]],
        "confidence": 0.7,
        "deterministic_rule_version": RULE_VERSION,
        "reviewer": dict(reviewer),
        "independent_from": independent_from[:256] or [hypothesis_id],
        "provenance": [
            provenance_record(
                created_at=created_at,
                source_uri=SOURCE_URI,
                material=verdict_id,
                raw_hash=raw_hash,
            )
        ],
    }
    return seal(record)


def run_gate_a(
    hypothesis: dict[str, Any],
    *,
    submission: dict[str, Any] | None = None,
    view: dict[str, Any] | None = None,
    analysis: dict[str, Any] | None = None,
    created_at: str | None = None,
    reconcile: bool = False,
    reviewer: dict[str, Any] | None = None,
    transcript_hash: str | None = None,
) -> dict[str, Any]:
    """Validate one blind challenger submission and build its sealed record.

    No model calls. The caller (evidence service) seals the returned record
    before any reconciliation attaches (blind-first, §5.5).
    """

    status = str(hypothesis.get("status") or "lead")
    grade = str(hypothesis.get("evidence_grade") or "lead")
    if isinstance(analysis, dict) and ("verdict" in analysis or "proposed_verdict" in analysis):
        raise EvidenceError(
            VERDICT_OVERRIDE_FORBIDDEN,
            "caller-supplied verdicts are forbidden; verdicts enter only through "
            "the challenger submission credential",
            details={"hypothesis_id": str(hypothesis.get("hypothesis_id") or "")},
        )
    if status != "supported" and not (isinstance(analysis, dict) and analysis.get("allow_non_supported")):
        raise EvidenceError(
            GATE_PRECONDITION,
            f"Gate A requires a supported hypothesis, not {status}",
            details={"status": status, "evidence_grade": grade},
        )
    if grade == "lead":
        raise EvidenceError(
            EVIDENCE_CEILING,
            "Gate A refuses a lead evidence grade; a poc_worthy verdict on a lead is rejected",
            details={"evidence_grade": grade},
        )
    if submission is None:
        raise EvidenceError(
            SUBMISSION_INVALID,
            "Gate A requires the challenger submission; there is no deterministic "
            "fallback decider",
        )
    if not isinstance(reviewer, dict) or not str(reviewer.get("id") or ""):
        raise EvidenceError(
            SUBMISSION_INVALID,
            "reviewer identity must be stamped by the evidence service from the "
            "submission credential, never caller-asserted",
        )
    normalized = validate_submission(submission)
    invariant = {
        "statement": normalized["violated_invariant"],
        "formulas": [normalized["violated_invariant"][:512]],
    }
    experiment = normalized["cheapest_decisive_experiment"]
    killed: list[str] = (
        [f"claimed-invariant:{normalized['violated_invariant'][:80]}"]
        if normalized["verdict"] == "falsified"
        else []
    )
    untried = [dim for dim in PRECONDITION_DIMENSIONS]
    record = build_verdict_record(
        hypothesis=hypothesis,
        verdict=normalized["verdict"],
        invariant=invariant,
        preconditions=normalized["preconditions"],
        benign=normalized["strongest_benign_explanation"],
        facts=[str(item) for item in (submission.get("missing_facts") or []) if str(item).strip()],
        experiment=experiment,
        killed=killed,
        untried=untried,
        created_at=created_at or str(hypothesis.get("created_at") or ""),
        independent_from=[str(hypothesis["hypothesis_id"])],
        reviewer=reviewer,
        transcript_hash=transcript_hash,
    )
    result: dict[str, Any] = {
        "schema_version": "1.0.0",
        "verdict": normalized["verdict"],
        "cannot_mark_surface_safe": True,
        "knowledge_blind": not reconcile,
        "invariant": invariant,
        "preconditions": normalized["preconditions"],
        "benign_explanation": normalized["strongest_benign_explanation"],
        "missing_facts": [
            str(item)[:512] for item in (submission.get("missing_facts") or []) if str(item).strip()
        ],
        "experiment": experiment,
        "killed_dimensions": killed,
        "untried_dimensions": untried,
        "reviewer": dict(reviewer),
        "record": record,
    }
    return result
