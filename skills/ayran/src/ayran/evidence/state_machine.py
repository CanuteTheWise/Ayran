"""Hypothesis state machine: the only legal path for status changes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ayran.evidence.actors import actor_is_authorized, actor_kind
from ayran.evidence.errors import (
    EVIDENCE_CEILING,
    MISSING_EVIDENCE,
    TRANSITION_REJECTED,
    UNAUTHORIZED_ACTOR,
    EvidenceError,
)
from ayran.evidence.types import (
    CEILING_BLOCKED_TARGETS,
    LADDER,
    STATES,
    STATUS_TO_GRADE,
    TERMINAL,
    as_str_list,
)

LEGAL: dict[str, frozenset[str]] = {
    "lead": frozenset(
        {
            "supported",
            "falsified",
            "needs_missing_fact",
            "needs_reformulation",
            "parked",
            "duplicate_known_issue",
        }
    ),
    "supported": frozenset(
        {"poc_worthy", "falsified", "needs_missing_fact", "needs_reformulation"}
    ),
    "poc_worthy": frozenset({"observed", "needs_reformulation", "parked"}),
    "observed": frozenset({"defect_pinned", "needs_reformulation", "falsified"}),
    "defect_pinned": frozenset({"validated", "duplicate_known_issue"}),
    "validated": frozenset({"reported"}),
    "falsified": frozenset(),
    "needs_missing_fact": frozenset(),
    "needs_reformulation": frozenset(),
    "parked": frozenset(),
    "duplicate_known_issue": frozenset(),
    "reported": frozenset(),
}

# Fields that must be present (non-empty) on the evidence payload.
REQUIRED_FIELDS: dict[tuple[str, str], tuple[str, ...]] = {
    ("lead", "supported"): ("path", "invariant", "source_span"),
    ("supported", "poc_worthy"): ("gate_a_verdict_id", "experiment"),
    ("poc_worthy", "observed"): ("reproduction_id",),
    ("observed", "defect_pinned"): ("negative_control_ids", "fix_evidence_ids"),
    ("defect_pinned", "validated"): (
        "skeptic_id",
        "scope_id",
        "impact_id",
        "dedup_id",
        "severity_id",
    ),
    ("validated", "reported"): ("report_id", "linter_pass"),
    ("lead", "falsified"): ("killed_dimension", "counterevidence"),
    ("supported", "falsified"): ("killed_dimension", "counterevidence"),
    ("observed", "falsified"): ("killed_dimension", "counterevidence"),
    ("lead", "needs_missing_fact"): ("named_fact", "why_decisive"),
    ("supported", "needs_missing_fact"): ("named_fact", "why_decisive"),
    ("lead", "needs_reformulation"): ("failed_premise",),
    ("supported", "needs_reformulation"): ("failed_premise",),
    ("poc_worthy", "needs_reformulation"): ("failed_premise",),
    ("observed", "needs_reformulation"): ("failed_premise",),
    ("lead", "parked"): ("reason", "wake_condition"),
    ("poc_worthy", "parked"): ("reason", "wake_condition"),
    ("lead", "duplicate_known_issue"): ("duplicate_of", "comparison"),
    ("defect_pinned", "duplicate_known_issue"): ("duplicate_of", "comparison"),
}


def _ladder_index(state: str) -> int:
    try:
        return LADDER.index(state)
    except ValueError:
        return -1


def is_demotion(current: str, target: str) -> bool:
    current_i = _ladder_index(current)
    target_i = _ladder_index(target)
    if current_i >= 0 and target_i >= 0:
        return target_i < current_i
    return current_i >= 0 and target in TERMINAL - {"reported"}


def is_legal_edge(current: str, target: str) -> bool:
    if current == target:
        return False
    if target not in STATES or current not in STATES:
        return False
    if target in LEGAL.get(current, frozenset()):
        return True
    return is_demotion(current, target)


def _present(payload: dict[str, Any], field: str) -> bool:
    value = payload.get(field)
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, dict)):
        return bool(value)
    return True


def missing_fields(current: str, target: str, evidence: dict[str, Any]) -> list[str]:
    required = REQUIRED_FIELDS.get((current, target), ())
    missing = [field for field in required if not _present(evidence, field)]
    if target == "supported":
        reachable = evidence.get("preconditions_reachable")
        if reachable is not True and not as_str_list(evidence.get("reachable_preconditions")):
            missing.append("reachable_preconditions")
    if target == "reported" and evidence.get("linter_pass") is not True and "linter_pass" not in missing:
        missing.append("linter_pass")
    return missing


def _ceiling_blocked(hypothesis: dict[str, Any], target: str) -> str | None:
    grade = str(hypothesis.get("evidence_grade") or "lead")
    status = str(hypothesis.get("status") or "lead")
    if target in CEILING_BLOCKED_TARGETS and (grade == "lead" or status == "lead"):
        return (
            "evidence ceiling: a lead cannot be promoted to "
            f"{target}; only a supported hypothesis may enter Gate A, "
            "and only observed tool evidence may enter Gate B"
        )
    if target in {"defect_pinned", "validated", "reported"} and grade not in {
        "observed",
        "defect_pinned",
        "validated",
    }:
        return (
            "evidence ceiling: Gate B and later states require observed "
            f"tool evidence, not {grade}"
        )
    return None


@dataclass(slots=True)
class TransitionDecision:
    accepted: bool
    current: str
    target: str
    demotion: bool
    missing: list[str] = field(default_factory=list)
    reason: str = ""
    next_grade: str = "lead"
    kind: str = "snapshot"

    def as_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "from": self.current,
            "to": self.target,
            "demotion": self.demotion,
            "missing": list(self.missing),
            "reason": self.reason,
            "next_grade": self.next_grade,
            "kind": self.kind,
        }


class HypothesisStateMachine:
    """Pure checker. Persistence is the caller's responsibility."""

    def evaluate(
        self,
        hypothesis: dict[str, Any],
        target: str,
        *,
        actor: dict[str, Any],
        evidence: dict[str, Any] | None = None,
        cause: str | None = None,
    ) -> TransitionDecision:
        current = str(hypothesis.get("status") or "lead")
        payload = evidence or {}
        demotion = is_demotion(current, target)
        grade = str(hypothesis.get("evidence_grade") or "lead")
        mapped = STATUS_TO_GRADE.get(target)
        next_grade = mapped if mapped else grade
        kind = "retraction" if demotion else "snapshot"

        if target not in STATES:
            return TransitionDecision(
                False, current, target, demotion, reason=f"unknown state {target!r}", next_grade=grade
            )
        if current not in STATES:
            return TransitionDecision(
                False, current, target, demotion, reason=f"unknown current state {current!r}",
                next_grade=grade,
            )
        if current == target:
            return TransitionDecision(
                False, current, target, False, reason="already in the requested state", next_grade=grade
            )
        if current in TERMINAL and not demotion:
            return TransitionDecision(
                False,
                current,
                target,
                False,
                reason=f"{current} is terminal; no further promotion is legal",
                next_grade=grade,
            )
        if not is_legal_edge(current, target):
            return TransitionDecision(
                False,
                current,
                target,
                demotion,
                reason=(
                    f"illegal transition {current} -> {target}; "
                    f"legal targets are {sorted(LEGAL.get(current, frozenset()))}"
                ),
                next_grade=grade,
            )
        mermaid = target in LEGAL.get(current, frozenset())
        if demotion and not mermaid and not (cause or payload.get("cause") or payload.get("reason")):
            return TransitionDecision(
                False,
                current,
                target,
                True,
                missing=["cause"],
                reason="demotion requires a cause; history is never overwritten",
                next_grade=grade,
                kind="retraction",
            )
        if not actor_is_authorized(actor, target):
            return TransitionDecision(
                False,
                current,
                target,
                demotion,
                reason=(
                    f"actor kind {actor_kind(actor)!r} cannot authorize {target}; "
                    "the state machine rejects unauthorized actors"
                ),
                next_grade=grade,
                kind=kind,
            )
        ceiling = _ceiling_blocked(hypothesis, target)
        if ceiling and not demotion:
            return TransitionDecision(
                False, current, target, False, reason=ceiling, next_grade=grade
            )
        missing = missing_fields(current, target, payload)
        if missing:
            return TransitionDecision(
                False,
                current,
                target,
                demotion,
                missing=missing,
                reason="insufficient evidence: missing " + ", ".join(missing),
                next_grade=grade,
                kind=kind,
            )
        return TransitionDecision(
            True,
            current,
            target,
            demotion,
            reason=str(cause or payload.get("cause") or payload.get("reason") or "legal transition"),
            next_grade=next_grade,
            kind=kind,
        )

    def require(
        self,
        hypothesis: dict[str, Any],
        target: str,
        *,
        actor: dict[str, Any],
        evidence: dict[str, Any] | None = None,
        cause: str | None = None,
    ) -> TransitionDecision:
        decision = self.evaluate(
            hypothesis, target, actor=actor, evidence=evidence, cause=cause
        )
        if decision.accepted:
            return decision
        code = TRANSITION_REJECTED
        if decision.missing:
            code = MISSING_EVIDENCE
        elif "actor kind" in decision.reason:
            code = UNAUTHORIZED_ACTOR
        elif "ceiling" in decision.reason:
            code = EVIDENCE_CEILING
        raise EvidenceError(code, decision.reason, details=decision.as_dict())
