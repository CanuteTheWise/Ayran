"""Driver 2 — Global-Graph-grounded leads. Mechanism cards before incidents."""

from __future__ import annotations

from ayran.context.view import GraphView
from ayran.hypotheses.builders import build_hypothesis
from ayran.hypotheses.drivers.base import DriverResult

NAME = "global_graph"
ORIGIN = "global_graph"
BUDGET = 15
MAX_MECHANISMS = 5
MAX_INCIDENTS = 3


def propose(view: GraphView) -> DriverResult:
    created = view.created_at
    mechanisms = list(view.global_mechanisms)[:MAX_MECHANISMS]
    incidents = list(view.global_incidents)[:MAX_INCIDENTS]
    hypotheses = []
    if view.knowledge_policy in {"target_only", "knowledge_blind"}:
        return DriverResult(
            driver=NAME,
            origin=ORIGIN,
            stop=True,
            stop_reason="knowledge_blind_or_target_only",
            source_id=NAME,
        )
    cards = mechanisms + incidents
    if not cards:
        hypotheses.append(
            build_hypothesis(
                origin=ORIGIN,
                claim=(
                    "Global-graph driver: no mechanism cards available; record a retrieval gap "
                    f"for cluster {view.cluster_id} rather than inventing historical matches."
                ),
                cluster_id=view.cluster_id,
                run_id=view.run_id,
                created_at=created,
                attack_path=["await diverse mechanism retrieval"],
                target_entities=[],
                preconditions=["Global Graph pack is empty"],
                novelty="unknown",
                trust_class="curated_external",
                root_cause="retrieval-gap",
                state=view.cluster_id,
                attacker="unprivileged",
                target_identity=view.target_identity or None,
            )
        )
    for index, card in enumerate(cards):
        title = str(card.get("title") or card.get("name") or f"card-{index}")
        kind = "mechanism" if index < len(mechanisms) else "incident"
        hypotheses.append(
            build_hypothesis(
                origin=ORIGIN,
                claim=(
                    f"Historical {kind} {title!r} may be applicable to cluster {view.cluster_id}; "
                    "treat as guidance, never as target evidence."
                ),
                cluster_id=view.cluster_id,
                run_id=view.run_id,
                created_at=created,
                attack_path=[f"map {title} onto target path", "require target invariant"],
                target_entities=[],
                preconditions=["target features overlap the retrieved mechanism"],
                novelty="known_mechanism" if kind == "mechanism" else "variant",
                trust_class="curated_external",
                root_cause=f"global:{kind}:{title}",
                state=view.cluster_id,
                attacker="unprivileged",
                target_identity=view.target_identity or None,
            )
        )
    return DriverResult(
        driver=NAME,
        origin=ORIGIN,
        hypotheses=hypotheses,
        material=bool(cards),
        units_spent=min(BUDGET, 3 + len(hypotheses)),
        source_id=NAME,
        stop=not cards,
        stop_reason="" if cards else "relevance_below_threshold",
    )
