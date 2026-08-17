"""Persist M5 cognitive objects through GraphStore.append only."""

from __future__ import annotations

from typing import Any

from ayran.api.validators import validate_contract
from ayran.context.contracts import ACTOR_ROUTER, graph_node, typed_property
from ayran.context.ids import content_id
from ayran.graph.canonical import utc_now
from ayran.graph.recovery import GraphStore
from ayran.graph.types import AppendCommand, AppendItem
from ayran.hypotheses.drivers.base import DRIVER_NAMES, DriverResult
from ayran.router.engine import StepResult

ZERO_HASH = "sha256:" + "0" * 64
CONFIG_HASH = ZERO_HASH
SOURCE_VERSION = "1.0.0"


def _strip_private(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if not str(key).startswith("_")}


def persist_hypotheses(store: GraphStore, hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    acks: list[dict[str, Any]] = []
    for item in hypotheses:
        value = _strip_private(item)
        validate_contract("hypothesis", value)
        identifier = str(value["hypothesis_id"])
        if store.projection.aggregate_revision(identifier):
            continue
        command = AppendCommand(
            f"hypothesis:{identifier}",
            (AppendItem("hypothesis@1.0.0", "hypothesis.recorded", value),),
            {identifier: store.projection.aggregate_revision(identifier)},
            {"kind": "service", "id": "ayran.hypotheses", "version": "1.0.0"},
            CONFIG_HASH,
            SOURCE_VERSION,
            created_at=str(value.get("created_at") or utc_now()),
        )
        acks.append(store.append(command))
    return acks


def persist_router_actions(store: GraphStore, actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    acks: list[dict[str, Any]] = []
    for item in actions:
        value = _strip_private(item)
        validate_contract("router-action", value)
        identifier = str(value["router_action_id"])
        current = store.projection.aggregate_revision(identifier)
        if current:
            continue
        command = AppendCommand(
            f"router-action:{identifier}",
            (AppendItem("router-action@1.0.0", "router_action.recorded", value),),
            {identifier: 0},
            ACTOR_ROUTER,
            CONFIG_HASH,
            SOURCE_VERSION,
            created_at=str(value.get("created_at") or utc_now()),
        )
        acks.append(store.append(command))
    return acks


def persist_coverage_cells(store: GraphStore, cells: list[dict[str, Any]]) -> list[dict[str, Any]]:
    acks: list[dict[str, Any]] = []
    for item in cells:
        value = _strip_private(item)
        validate_contract("coverage-cell", value)
        identifier = str(value["coverage_cell_id"])
        command = AppendCommand(
            f"coverage:{identifier}:{value.get('updated_at')}",
            (AppendItem("coverage-cell@1.0.0", "coverage_cell.recorded", value),),
            {identifier: store.projection.aggregate_revision(identifier)},
            ACTOR_ROUTER,
            CONFIG_HASH,
            SOURCE_VERSION,
            created_at=str(value.get("created_at") or utc_now()),
        )
        acks.append(store.append(command))
    return acks


def persist_graph_objects(
    store: GraphStore,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> dict[str, Any]:
    items: list[AppendItem] = []
    expected: dict[str, int] = {}
    for node in nodes:
        identifier = str(node["node_id"])
        if store.projection.aggregate_revision(identifier):
            continue
        items.append(AppendItem("graph-node@1.0.0", "node.created", node))
        expected[identifier] = 0
    for edge in edges:
        identifier = str(edge["edge_id"])
        if store.projection.aggregate_revision(identifier):
            continue
        items.append(AppendItem("graph-edge@1.0.0", "edge.created", edge))
        expected[identifier] = 0
    if not items:
        return {"appended": 0}
    command = AppendCommand(
        f"maps:{items[0].value.get('node_id') or items[0].value.get('edge_id')}:{len(items)}",
        tuple(items),
        expected,
        {"kind": "service", "id": "ayran.mapping", "version": "1.0.0"},
        CONFIG_HASH,
        SOURCE_VERSION,
        created_at=str(items[0].value.get("created_at") or utc_now()),
    )
    return store.append(command)


def persist_driver_results(store: GraphStore, results: dict[str, DriverResult]) -> None:
    hypotheses: list[dict[str, Any]] = []
    for result in results.values():
        hypotheses.extend(result.hypotheses)
    persist_hypotheses(store, hypotheses)


def persist_runtime_node(store: GraphStore, node: dict[str, Any]) -> dict[str, Any]:
    identifier = str(node["node_id"])
    current = store.projection.aggregate_revision(identifier)
    event_type = "node.created" if current == 0 else "node.revised"
    command = AppendCommand(
        f"runtime:{identifier}:{current + 1}",
        (AppendItem("graph-node@1.0.0", event_type, node),),
        {identifier: current},
        ACTOR_ROUTER,
        CONFIG_HASH,
        SOURCE_VERSION,
        created_at=str(node.get("created_at") or utc_now()),
    )
    return store.append(command)


def persist_router_runtime(
    store: GraphStore,
    *,
    cluster_id: str,
    run_id: str,
    created_at: str,
    result: StepResult,
    killed: set[str],
    kill_streaks: dict[str, int],
    no_progress_cycles: int,
    freeze_hash: str,
    target_first_completed: bool,
) -> None:
    """Write revisable router control nodes so later steps restore from the graph."""

    nodes: list[dict[str, Any]] = []
    freeze = freeze_hash if freeze_hash.startswith("sha256:") else ZERO_HASH
    nodes.append(
        graph_node(
            node_id=content_id("nod", "target-first", cluster_id),
            node_type="TargetFirstSnapshot",
            run_id=run_id,
            created_at=created_at,
            source_locator=f"router:target-first:{cluster_id}",
            trust_class="runtime_observation",
            properties=[
                typed_property("cluster_id", cluster_id),
                typed_property("snapshot_hash", freeze),
                typed_property("completed", target_first_completed, "boolean"),
                typed_property("title", "target-first"),
            ],
        )
    )
    spent = result.budget.get("spent") or {}
    for name in DRIVER_NAMES:
        nodes.append(
            graph_node(
                node_id=content_id("nod", "driver-state", name, cluster_id),
                node_type="DriverState",
                run_id=run_id,
                created_at=created_at,
                source_locator=f"router:driver:{name}",
                trust_class="runtime_observation",
                properties=[
                    typed_property("driver", name),
                    typed_property("cluster_id", cluster_id),
                    typed_property("killed", name in killed, "boolean"),
                    typed_property("no_progress", int(kill_streaks.get(name) or 0), "integer"),
                    typed_property("spend", int(spent.get(name) or 0), "integer"),
                    typed_property("title", name),
                ],
            )
        )
    nodes.append(
        graph_node(
            node_id=content_id("nod", "router-budget", cluster_id),
            node_type="RouterBudget",
            run_id=run_id,
            created_at=created_at,
            source_locator="router:budget",
            trust_class="runtime_observation",
            properties=[
                typed_property("remaining", int(result.budget.get("remaining") or 0), "integer"),
                typed_property("spent", int(sum(int(value) for value in spent.values())), "integer"),
                typed_property("tranche", int(result.budget.get("tranche") or 100), "integer"),
                typed_property(
                    "reserve_released",
                    bool(result.budget.get("reserve_released")),
                    "boolean",
                ),
                typed_property("title", "budget"),
            ],
        )
    )
    nodes.append(
        graph_node(
            node_id=content_id("nod", "router-control", cluster_id),
            node_type="RouterControl",
            run_id=run_id,
            created_at=created_at,
            source_locator="router:control",
            trust_class="runtime_observation",
            properties=[
                typed_property("no_progress_cycles", int(no_progress_cycles), "integer"),
                typed_property("manual_next", result.manual_next, "boolean"),
                typed_property("dual_review", False, "boolean"),
                typed_property("title", "control"),
            ],
        )
    )
    for node in nodes:
        persist_runtime_node(store, node)
