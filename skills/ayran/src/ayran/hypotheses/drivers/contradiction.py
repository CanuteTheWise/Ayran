"""Driver 3 — contradiction-derived hypotheses from conflicting assertions."""

from __future__ import annotations

from ayran.context.view import GraphView
from ayran.hypotheses.builders import build_hypothesis
from ayran.hypotheses.drivers.base import DriverResult

NAME = "contradiction"
ORIGIN = "contradiction"
BUDGET = 15


def propose(view: GraphView) -> DriverResult:
    created = view.created_at
    groups = list(view.contradictions)
    # Sibling-path asymmetry from coverage cells sharing a prefix.
    dimensions = [str(cell.get("dimension") or "") for cell in view.coverage_cells]
    if len(set(item.split(":")[0] for item in dimensions if item)) >= 1 and len(dimensions) >= 2:
        groups.append(
            {
                "id": "coverage-asymmetry",
                "left": dimensions[0],
                "right": dimensions[1],
                "kind": "sibling-path-asymmetry",
            }
        )
    hypotheses = []
    if not groups:
        hypotheses.append(
            build_hypothesis(
                origin=ORIGIN,
                claim=(
                    f"Contradiction scan of cluster {view.cluster_id}: no conflicting assertions "
                    "are recorded; keep a watcher on spec/code and conservation mismatches."
                ),
                cluster_id=view.cluster_id,
                run_id=view.run_id,
                created_at=created,
                attack_path=["compare sibling paths", "check conservation"],
                target_entities=[],
                preconditions=["two assertions about the same valued state"],
                novelty="unknown",
                trust_class="model_observation",
                root_cause="contradiction-watch",
                state=view.cluster_id,
                attacker="unprivileged",
                target_identity=view.target_identity or None,
            )
        )
    for group in groups[:6]:
        kind = str(group.get("kind") or "conflict")
        left = str(group.get("left") or "assertion-a")
        right = str(group.get("right") or "assertion-b")
        hypotheses.append(
            build_hypothesis(
                origin=ORIGIN,
                claim=(
                    f"Contradiction ({kind}): {left} conflicts with {right} on cluster "
                    f"{view.cluster_id}; a decisive experiment is required."
                ),
                cluster_id=view.cluster_id,
                run_id=view.run_id,
                created_at=created,
                attack_path=["pin both spans", "run cheaper higher-trust check"],
                target_entities=[],
                preconditions=["both assertions remain current"],
                novelty="unknown",
                trust_class="model_observation",
                root_cause=f"contradiction:{kind}:{left}:{right}",
                state=view.cluster_id,
                attacker="unprivileged",
                target_identity=view.target_identity or None,
                required_falsifiers=["Higher-trust evidence resolves the conflict as benign"],
            )
        )
    return DriverResult(
        driver=NAME,
        origin=ORIGIN,
        hypotheses=hypotheses,
        experiments=["Execute the cheaper decisive experiment on the contradiction group."],
        material=bool(view.contradictions),
        units_spent=min(BUDGET, 4 + len(hypotheses)),
        source_id=NAME,
    )
