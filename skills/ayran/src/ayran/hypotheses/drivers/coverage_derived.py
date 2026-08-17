"""Driver 5 — coverage-derived hypotheses for risk-weighted uncovered cells."""

from __future__ import annotations

from ayran.context.view import GraphView
from ayran.hypotheses.builders import build_hypothesis
from ayran.hypotheses.drivers.base import DriverResult
from ayran.mapping.coverage import grid_from_cells

NAME = "coverage_derived"
ORIGIN = "coverage"
BUDGET = 15


def propose(view: GraphView) -> DriverResult:
    created = view.created_at
    grid = grid_from_cells(view.cluster_id, view.coverage_cells)
    uncovered = grid.get_risk_weighted_uncovered(threshold=0)
    hypotheses = []
    deltas = []
    if not uncovered and not view.coverage_cells:
        hypotheses.append(
            build_hypothesis(
                origin=ORIGIN,
                claim=(
                    f"Coverage driver: cluster {view.cluster_id} has no coverage cells; "
                    "seed the risk-weighted grid before closing any surface."
                ),
                cluster_id=view.cluster_id,
                run_id=view.run_id,
                created_at=created,
                attack_path=["inventory entry points", "mark untried dimensions"],
                target_entities=[],
                preconditions=["mapping integrity is incomplete"],
                novelty="unknown",
                trust_class="model_observation",
                root_cause="coverage-unseeded",
                state=view.cluster_id,
                attacker="unprivileged",
                target_identity=view.target_identity or None,
            )
        )
    for cell in uncovered[:8]:
        dimension = str(cell.get("dimension") or "unspecified")
        hypotheses.append(
            build_hypothesis(
                origin=ORIGIN,
                claim=(
                    f"Uncovered high-value cell {dimension} on cluster {view.cluster_id}; "
                    "activity alone cannot close it."
                ),
                cluster_id=view.cluster_id,
                run_id=view.run_id,
                created_at=created,
                attack_path=["examine cell", "record exact dimension", "leave untried siblings open"],
                target_entities=[str(cell.get("coverage_cell_id"))]
                if cell.get("coverage_cell_id")
                else [],
                preconditions=["cell remains open"],
                novelty="unknown",
                trust_class="model_observation",
                root_cause=f"coverage:{dimension}",
                state=view.cluster_id,
                attacker="unprivileged",
                target_identity=view.target_identity or None,
            )
        )
        deltas.append(
            {
                "coverage_cell_id": cell.get("coverage_cell_id"),
                "new_state": "in_progress",
                "dimension": dimension,
            }
        )
    return DriverResult(
        driver=NAME,
        origin=ORIGIN,
        hypotheses=hypotheses,
        coverage_deltas=deltas,
        material=bool(uncovered),
        units_spent=min(BUDGET, 3 + len(hypotheses)),
        source_id=NAME,
        stop=not uncovered and bool(view.coverage_cells),
        stop_reason="" if uncovered or not view.coverage_cells else "cells_have_bounded_evidence",
    )
