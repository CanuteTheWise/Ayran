"""Versioned engagement severity policies. Historical labels are calibration only."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from ayran.evidence.types import DEFAULT_SEVERITY_POLICY_ID, as_mapping

POLICIES: dict[str, dict[str, Any]] = {
    DEFAULT_SEVERITY_POLICY_ID: {
        "policy_id": DEFAULT_SEVERITY_POLICY_ID,
        "version": "1.0.0",
        "name": "ayran.contest.default",
        "rules": (
            {
                "id": "R1-critical-theft",
                "label": "critical",
                "when": "theft-or-loss and upper_bound >= 1e18 and unprivileged",
            },
            {
                "id": "R2-high-theft",
                "label": "high",
                "when": "theft-or-loss and unprivileged",
            },
            {
                "id": "R3-medium-lock",
                "label": "medium",
                "when": "lock-or-availability",
            },
            {
                "id": "R4-low-integrity",
                "label": "low",
                "when": "integrity-or-governance-with-privilege",
            },
            {
                "id": "R5-info",
                "label": "informational",
                "when": "default",
            },
        ),
    }
}


def _bound(value: Any) -> Decimal:
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return Decimal("0")


def assess_severity(
    impact: dict[str, Any],
    *,
    policy_id: str | None = None,
    preconditions_unprivileged: bool = True,
    ambiguities: list[str] | None = None,
) -> dict[str, Any]:
    identifier = policy_id or DEFAULT_SEVERITY_POLICY_ID
    policy = POLICIES.get(identifier) or POLICIES[DEFAULT_SEVERITY_POLICY_ID]
    identifier = str(policy["policy_id"])
    mapped = as_mapping(impact.get("finding_impact"))
    kind = str(mapped.get("kind") or impact.get("kind") or "integrity")
    profit = as_mapping(impact.get("profit_loss"))
    finding_impact = mapped
    upper = _bound(profit.get("upper_bound") or finding_impact.get("upper_bound") or 0)
    notes = list(ambiguities or [])
    claims = as_mapping(impact.get("deployment_claims"))
    if claims.get("claimed") and not claims.get("verified"):
        notes.append("deployment impact claimed without pinned bytecode identity")

    label = "informational"
    citation = "R5-info: default informational when no theft/loss/lock mapping applies"
    if kind in {"theft", "loss"} and preconditions_unprivileged and upper >= Decimal("1000000000000000000"):
        label = "critical"
        citation = "R1-critical-theft: unprivileged theft/loss with upper_bound >= 1e18 wei"
    elif kind in {"theft", "loss"} and preconditions_unprivileged:
        label = "high"
        citation = "R2-high-theft: unprivileged theft/loss"
    elif kind in {"lock", "availability"}:
        label = "medium"
        citation = "R3-medium-lock: lock or availability impact"
    elif kind in {"integrity", "governance"} and not preconditions_unprivileged:
        label = "low"
        citation = "R4-low-integrity: privileged integrity/governance"
    elif kind in {"integrity", "governance"}:
        label = "medium"
        citation = "R2-high-theft analog: unprivileged integrity mapped to medium under this policy"
        notes.append("integrity without quantified theft; medium under explicit assumption of user-facing break")

    alternatives: list[dict[str, Any]] = []
    if notes:
        alternatives.append(
            {
                "label": "informational",
                "assumption": "deployment identity fails; treat as non-production",
                "rule_citation": "R5-info under failed deployment identity",
            }
        )
    return {
        "schema_version": "1.0.0",
        "label": label,
        "policy_id": identifier,
        "policy_version": str(policy["version"]),
        "rule_citation": citation[:1024],
        "ambiguities": notes,
        "alternatives": alternatives,
        "historical_calibration_only": True,
        "finding_severity": {
            "label": label,
            "policy_id": identifier,
            "rule_citation": citation[:1024],
        },
    }
