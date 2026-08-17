"""Shared constants for the M6 evidence pipeline."""

from __future__ import annotations

from typing import Any

from ayran.context.ids import ZERO_HASH, content_id

RULE_VERSION = "1.0.0"
SOURCE_URI = "urn:ayran:m6:evidence"
CONFIG_HASH = ZERO_HASH

STATES = (
    "lead",
    "supported",
    "poc_worthy",
    "observed",
    "defect_pinned",
    "validated",
    "falsified",
    "needs_missing_fact",
    "needs_reformulation",
    "parked",
    "duplicate_known_issue",
    "reported",
)

LADDER = (
    "lead",
    "supported",
    "poc_worthy",
    "observed",
    "defect_pinned",
    "validated",
    "reported",
)

TERMINAL = frozenset({"falsified", "parked", "duplicate_known_issue", "reported"})

STATUS_TO_GRADE: dict[str, str | None] = {
    "lead": "lead",
    "supported": "supported",
    "poc_worthy": "supported",
    "observed": "observed",
    "defect_pinned": "defect_pinned",
    "validated": "validated",
    "reported": "validated",
    "falsified": None,
    "needs_missing_fact": None,
    "needs_reformulation": None,
    "parked": None,
    "duplicate_known_issue": None,
}

CEILING_BLOCKED_TARGETS = frozenset(
    {"poc_worthy", "observed", "defect_pinned", "validated", "reported"}
)

GATE_A_DECISIONS = ("falsified", "needs_missing_fact", "needs_reformulation", "poc_worthy")
GATE_B_DECISIONS = ("defect_pinned", "needs_reformulation", "falsified")

DECISION_TO_SCHEMA: dict[str, str] = {
    "poc_worthy": "advance",
    "defect_pinned": "advance",
    "falsified": "reject",
    "needs_missing_fact": "insufficient",
    "needs_reformulation": "revise",
    "duplicate_known_issue": "duplicate",
}

PRECONDITION_DIMENSIONS = (
    "require_guards",
    "modifiers",
    "access_boundaries",
    "slippage_deadline",
    "solvency",
    "rounding",
    "finality_timing",
    "token_behavior",
    "integration_behavior",
)

GATE_B_OBLIGATIONS = (
    "clean_replay",
    "numerical_assertions",
    "negative_controls",
    "defect_removal",
    "fix_efficacy",
    "alternate_paths",
    "independent_skeptic",
    "deployment_identity",
    "feasibility_scope_severity",
)

DEFAULT_SEVERITY_POLICY_ID = content_id("pol", "ayran.severity.contest", "1.0.0")
DEFAULT_SCOPE_ID = "scp_01J00000000000000000000001"


def as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


def as_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}
