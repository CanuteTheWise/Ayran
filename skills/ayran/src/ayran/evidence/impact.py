"""Numerical impact analysis. Not a severity score."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from ayran.context.ids import content_id
from ayran.evidence.types import as_mapping

KIND_MAP = {
    "asset_theft": "theft",
    "unbacked_claim": "theft",
    "debt_escape": "loss",
    "governance_takeover": "governance",
    "permanent_lock": "lock",
    "mev_extraction": "theft",
    "integrity_violation": "integrity",
    "availability": "availability",
}


def _decimal(value: Any) -> Decimal | None:
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def assess_impact(
    hypothesis: dict[str, Any],
    *,
    assumptions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = dict(assumptions or {})
    premise = as_mapping(hypothesis.get("impact_premise"))
    kind = KIND_MAP.get(str(premise.get("kind") or "integrity_violation"), "integrity")
    price = _decimal(payload.get("asset_price")) or Decimal("1")
    repeats = int(payload.get("repetitions") or 1)
    if repeats < 1:
        repeats = 1
    unit = _decimal(payload.get("unit_loss")) or _decimal(premise.get("upper_bound")) or Decimal("1")
    lower = unit * price
    upper = lower * Decimal(repeats)
    equation = str(
        payload.get("equation")
        or f"attacker_net = unit_loss * asset_price * repetitions = {unit} * {price} * {repeats}"
    )
    identity = as_mapping(hypothesis.get("target_identity"))
    record = {
        "schema_version": "1.0.0",
        "impact_id": content_id("imp", str(hypothesis.get("hypothesis_id") or ""), equation, str(repeats)),
        "hypothesis_id": str(hypothesis.get("hypothesis_id") or ""),
        "kind": kind,
        "attacker_model": {
            "reachability": str(payload.get("reachability") or "unprivileged external call"),
            "privileges": str(payload.get("privileges") or "none"),
            "capital_liquidity": str(payload.get("capital_liquidity") or "one deposit unit"),
            "fees_gas": str(payload.get("fees_gas") or "one transaction"),
            "ordering_timing": str(payload.get("ordering_timing") or "same-block optional"),
        },
        "profit_loss": {
            "equation": equation[:2048],
            "lower_bound": format(lower, "f"),
            "upper_bound": format(upper, "f"),
            "repetitions": repeats,
        },
        "asset_exposure": {
            "total_value_at_risk": str(payload.get("tvr") or format(upper, "f")),
            "affected_deployments": list(payload.get("affected_deployments") or [identity.get("commit") or "repo"]),
            "affected_users": str(payload.get("affected_users") or "depositors of the target"),
            "contagion": str(payload.get("contagion") or "none asserted"),
        },
        "recovery": {
            "post_exploit_state": str(payload.get("post_exploit_state") or "credited attacker, depleted vault"),
            "options": list(payload.get("recovery_options") or ["pause", "upgrade"]),
            "blast_radius": str(payload.get("blast_radius") or "single vault"),
        },
        "deployment_claims": {
            "claimed": payload.get("deployment_claimed") is True,
            "repo_source_hash": str(identity.get("source_tree_hash") or ""),
            "deployed_identity": str(payload.get("deployed_identity") or ""),
            "pinned_block": payload.get("pinned_block"),
            "verified": payload.get("deployment_verified") is True,
        },
        "assumptions": [
            f"asset_price={price}",
            f"time_window={payload.get('time_window') or 'single block'}",
            f"market_conditions={payload.get('market_conditions') or 'quoted price held'}",
            *[str(item) for item in (payload.get("extra_assumptions") or [])],
        ],
        "finding_impact": {
            "kind": kind,
            "equation": equation[:2048],
            "lower_bound": format(lower, "f")[:128],
            "upper_bound": format(upper, "f")[:128],
            "assumptions": [
                f"asset_price={price}",
                f"time_window={payload.get('time_window') or 'single block'}",
                f"market_conditions={payload.get('market_conditions') or 'quoted price held'}",
            ],
        },
    }
    return record
