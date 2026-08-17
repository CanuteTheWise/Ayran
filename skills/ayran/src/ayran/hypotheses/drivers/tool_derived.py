"""Driver 4 — tool-derived leads. Never promote a lead to observed."""

from __future__ import annotations

from ayran.context.view import GraphView
from ayran.hypotheses.builders import build_hypothesis
from ayran.hypotheses.drivers.base import DriverResult

NAME = "tool_derived"
ORIGIN = "tool"
BUDGET = 10


def propose(view: GraphView) -> DriverResult:
    created = view.created_at
    leads: list[dict[str, str]] = []
    for run in view.tool_runs:
        ceiling = str(run.get("evidence_ceiling") or "lead")
        tool_name = str(run.get("tool_name") or run.get("capability_id") or "tool")
        parse_status = str(run.get("parse_status") or "parsed")
        if parse_status in {"failed", "parser_drift"}:
            continue
        leads.append(
            {
                "tool": tool_name,
                "ceiling": ceiling,
                "run_id": str(run.get("tool_run_id") or ""),
            }
        )
    # Slither-shaped facts on the attack surface (still leads).
    surface = view.maps.get("attack_surface") or {}
    for name in surface.get("entry_points") or []:
        leads.append({"tool": "slither-or-source-map", "ceiling": "lead", "run_id": str(name)})
    unique = {(item["tool"], item["run_id"]): item for item in leads}
    leads = [unique[key] for key in sorted(unique)]
    hypotheses = []
    if not leads:
        hypotheses.append(
            build_hypothesis(
                origin=ORIGIN,
                claim=(
                    f"Tool driver: no normalized tool leads on cluster {view.cluster_id}; "
                    "static mapping checks remain eligible but are not evidence of safety."
                ),
                cluster_id=view.cluster_id,
                run_id=view.run_id,
                created_at=created,
                attack_path=["run pinned static adapter"],
                target_entities=[],
                preconditions=["adapter is healthy"],
                novelty="unknown",
                trust_class="deterministic_tool",
                root_cause="tool-empty",
                state=view.cluster_id,
                attacker="unprivileged",
                target_identity=view.target_identity or None,
            )
        )
    for item in leads[:8]:
        ceiling = item["ceiling"] if item["ceiling"] in {"lead", "supported", "observed"} else "lead"
        # Preserve evidence ceiling: even replayable tools stay leads in M5.
        hypotheses.append(
            build_hypothesis(
                origin=ORIGIN,
                claim=(
                    f"Tool lead from {item['tool']} (ceiling={ceiling}) on cluster "
                    f"{view.cluster_id}; rule IDs are not root cause."
                ),
                cluster_id=view.cluster_id,
                run_id=view.run_id,
                created_at=created,
                attack_path=["cluster semantically", "trace to source span"],
                target_entities=[],
                preconditions=["tool output hashes match the recorded ToolRun"],
                novelty="unknown",
                trust_class="deterministic_tool",
                root_cause=f"tool:{item['tool']}:{item['run_id']}",
                state=view.cluster_id,
                attacker="unprivileged",
                target_identity=view.target_identity or None,
            )
        )
    return DriverResult(
        driver=NAME,
        origin=ORIGIN,
        hypotheses=hypotheses,
        material=bool(view.tool_runs),
        units_spent=min(BUDGET, 2 + len(hypotheses)),
        source_id=NAME,
    )
