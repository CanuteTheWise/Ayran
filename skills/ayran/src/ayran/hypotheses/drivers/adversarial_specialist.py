"""Driver 6 — adversarial specialist. One primary plus at most one independent role."""

from __future__ import annotations

from ayran.context.view import GraphView
from ayran.hypotheses.builders import build_hypothesis
from ayran.hypotheses.drivers.base import DriverResult

NAME = "adversarial_specialist"
ORIGIN = "specialist"
BUDGET = 20

ROLE_BY_SIGNAL = (
    ("value_flow", "econ-analyst"),
    ("authority", "code-reviewer"),
    ("temporal", "formal-methods"),
    ("attack_surface", "attack-mapper"),
    ("control_flow", "bug-hunter"),
)


def _roles_for(view: GraphView) -> list[str]:
    roles: list[str] = []
    for key, role in ROLE_BY_SIGNAL:
        if key in view.maps:
            roles.append(role)
    if view.value_at_risk >= 40 and "bug-hunter" not in roles:
        roles.append("bug-hunter")
    if view.dual_review:
        roles.append("devils-advocate")
    unique: list[str] = []
    for role in roles:
        if role not in unique:
            unique.append(role)
    return unique[:2]


def propose(view: GraphView) -> DriverResult:
    created = view.created_at
    roles = _roles_for(view)
    if not roles:
        roles = ["bug-hunter"]
    hypotheses = []
    blind = view.knowledge_policy in {"knowledge_blind", "target_only"}
    for role in roles:
        mode = "blind" if blind else "aware"
        hypotheses.append(
            build_hypothesis(
                origin=ORIGIN,
                claim=(
                    f"Specialist {role} ({mode}) reviews cluster {view.cluster_id} for "
                    "independent diversity; historical names are excluded in blind mode."
                ),
                cluster_id=view.cluster_id,
                run_id=view.run_id,
                created_at=created,
                attack_path=[f"{role} inspects assigned cells", "write counterevidence or missing facts"],
                target_entities=[],
                preconditions=["independence group is intact"],
                novelty="unknown",
                trust_class="model_observation",
                root_cause=f"specialist:{role}:{mode}",
                state=view.cluster_id,
                attacker="unprivileged",
                target_identity=view.target_identity or None,
            )
        )
        if view.dual_review and not blind:
            hypotheses.append(
                build_hypothesis(
                    origin=ORIGIN,
                    claim=(
                        f"Aware-phase specialist {role} re-evaluates cluster {view.cluster_id} "
                        "after Global pack retrieval; disagreement with the blind pass is telemetry."
                    ),
                    cluster_id=view.cluster_id,
                    run_id=view.run_id,
                    created_at=created,
                    attack_path=["compare blind vs aware dispositions"],
                    target_entities=[],
                    preconditions=["blind snapshot hash is frozen"],
                    novelty="unknown",
                    trust_class="model_observation",
                    root_cause=f"specialist:{role}:aware-disagreement",
                    state=view.cluster_id,
                    attacker="unprivileged",
                    target_identity=view.target_identity or None,
                )
            )
    return DriverResult(
        driver=NAME,
        origin=ORIGIN,
        hypotheses=hypotheses[:8],
        material=True,
        units_spent=min(BUDGET, 8 + 4 * len(roles)),
        source_id=NAME,
    )
