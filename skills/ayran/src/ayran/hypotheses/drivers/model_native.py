"""Driver 1 — model-native first principles. No historical or tool-alert anchors."""

from __future__ import annotations

from ayran.context.view import GraphView
from ayran.hypotheses.builders import build_hypothesis
from ayran.hypotheses.drivers.base import DriverResult
from ayran.mapping.source import parse_solidity

NAME = "model_native"
ORIGIN = "model_novel"
BUDGET = 25


def propose(view: GraphView) -> DriverResult:
    """Produce first-principles hypotheses from target source and maps only."""

    created = view.created_at
    run_id = view.run_id
    cluster = view.cluster_id
    identity = view.target_identity or None
    # Explicitly ignore retrieved cards and tool alerts.
    _ = view.global_mechanisms
    _ = view.global_incidents
    _ = view.tool_runs
    functions: list[dict[str, str]] = []
    source_blob = ""
    for unit in view.source_units:
        if unit.get("source"):
            source_blob += "\n" + str(unit["source"])
        if unit.get("kind") == "function" or unit.get("name"):
            functions.append(
                {
                    "name": str(unit.get("name") or "unknown"),
                    "visibility": str(unit.get("visibility") or "public"),
                }
            )
    surface = view.maps.get("attack_surface") or {}
    for name in surface.get("entry_points") or []:
        functions.append({"name": str(name), "visibility": "external"})
    if source_blob:
        parsed = parse_solidity(source_blob)
        for item in parsed["functions"]:
            functions.append({"name": str(item["name"]), "visibility": str(item["visibility"])})
    unique: dict[str, dict[str, str]] = {}
    for item in functions:
        unique[item["name"]] = item
    functions = [unique[key] for key in sorted(unique)]
    hypotheses: list[dict[str, object]] = []
    if functions:
        for item in functions[:6]:
            if item["visibility"] not in {"public", "external"}:
                continue
            claim = (
                f"First-principles: {item['name']} may violate a value or authorization invariant "
                f"on cluster {cluster} without retrieved or tool anchors."
            )
            hypotheses.append(
                build_hypothesis(
                    origin=ORIGIN,
                    claim=claim,
                    cluster_id=cluster,
                    run_id=run_id,
                    created_at=created,
                    attack_path=[f"enter {item['name']}", "mutate privileged or valued state"],
                    target_entities=[],
                    preconditions=[f"attacker can call {item['name']}"],
                    novelty="no_known_precedent",
                    trust_class="model_observation",
                    root_cause=f"unexamined-entry:{item['name']}",
                    state=cluster,
                    attacker="unprivileged",
                    target_identity=identity,
                    next_evidence="reachable path, invariant, and attacker-creatable preconditions",
                )
            )
    if not hypotheses:
        hypotheses.append(
            build_hypothesis(
                origin=ORIGIN,
                claim=(
                    f"First-principles exploration of cluster {cluster}: unknown invariants may be "
                    "violated by unprivileged composition of in-scope entry points."
                ),
                cluster_id=cluster,
                run_id=run_id,
                created_at=created,
                attack_path=["map entry points", "invert assumptions", "compose state"],
                target_entities=[],
                preconditions=["cluster source is in scope"],
                novelty="unknown",
                trust_class="model_observation",
                root_cause="open-exploration",
                state=cluster,
                attacker="unprivileged",
                target_identity=identity,
            )
        )
    # Novel invariant request is encoded as an experiment, not a fact.
    experiments = [
        "Propose a conservation invariant over valued state and attempt to break it from each external entry."
    ]
    return DriverResult(
        driver=NAME,
        origin=ORIGIN,
        hypotheses=hypotheses,
        experiments=experiments,
        material=True,
        units_spent=min(BUDGET, 5 + len(hypotheses)),
        source_id=NAME,
    )
