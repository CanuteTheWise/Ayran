"""Shared map node/edge helpers. Maps are built from tools/source, never model inference."""

from __future__ import annotations

from typing import Any

from ayran.context.contracts import graph_edge, graph_node, typed_property
from ayran.context.ids import content_id

MAP_NODE_TYPES = (
    "AttackSurfaceMap",
    "ControlFlowMap",
    "DataFlowMap",
    "ValueFlowMap",
    "AuthorityMap",
    "TemporalMap",
    "ValueAtRiskMap",
    "SpecDivergenceMap",
    "IntegrationAssumptionMap",
)


def node_id(kind: str, *parts: str) -> str:
    return content_id("nod", kind, *parts)


def edge_id(kind: str, *parts: str) -> str:
    return content_id("edg", kind, *parts)


def function_node(
    *,
    run_id: str,
    created_at: str,
    name: str,
    visibility: str,
    locator: str,
    extra: dict[str, str | int | bool | None] | None = None,
) -> dict[str, Any]:
    props = [
        typed_property("canonical_key", f"function:{name}:{locator}"),
        typed_property("name", name),
        typed_property("title", name),
        typed_property("visibility", visibility),
    ]
    for key, value in sorted((extra or {}).items()):
        if isinstance(value, bool):
            props.append(typed_property(key, value, "boolean"))
        elif isinstance(value, int):
            props.append(typed_property(key, value, "integer"))
        elif value is not None:
            props.append(typed_property(key, str(value)))
    return graph_node(
        node_id=node_id("function", name, locator),
        node_type="Function",
        run_id=run_id,
        created_at=created_at,
        source_locator=locator,
        properties=props,
    )


def state_node(
    *,
    run_id: str,
    created_at: str,
    name: str,
    locator: str,
) -> dict[str, Any]:
    return graph_node(
        node_id=node_id("state", name, locator),
        node_type="StateVariable",
        run_id=run_id,
        created_at=created_at,
        source_locator=locator,
        properties=[
            typed_property("canonical_key", f"state:{name}:{locator}"),
            typed_property("name", name),
            typed_property("title", name),
        ],
    )


def map_summary_node(
    *,
    map_type: str,
    cluster_id: str,
    run_id: str,
    created_at: str,
    payload: str,
    extra: dict[str, str | int | bool | None] | None = None,
) -> dict[str, Any]:
    props = [
        typed_property("canonical_key", f"map:{map_type}:{cluster_id}"),
        typed_property("cluster_id", cluster_id),
        typed_property("payload", payload[:2000] if len(payload) > 2000 else payload),
        typed_property("title", map_type),
    ]
    for key, value in sorted((extra or {}).items()):
        if isinstance(value, bool):
            props.append(typed_property(key, value, "boolean"))
        elif isinstance(value, int):
            props.append(typed_property(key, value, "integer"))
        elif value is not None:
            props.append(typed_property(key, str(value)))
    return graph_node(
        node_id=node_id("map", map_type, cluster_id),
        node_type=map_type,
        run_id=run_id,
        created_at=created_at,
        source_locator=f"map:{map_type}",
        properties=props,
    )


def call_edge(
    *,
    source_id: str,
    target_id: str,
    run_id: str,
    created_at: str,
    locator: str,
    edge_type: str = "CALLS",
) -> dict[str, Any]:
    return graph_edge(
        edge_id=edge_id(edge_type.lower(), source_id, target_id),
        edge_type=edge_type,
        source_id=source_id,
        target_id=target_id,
        run_id=run_id,
        created_at=created_at,
        source_locator=locator,
    )
