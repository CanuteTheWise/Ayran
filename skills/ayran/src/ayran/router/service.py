"""Sidecar/CLI facade for M5 compile, router, coverage, and maps."""

from __future__ import annotations

from typing import Any

from ayran.context.compiler import compile_with_injection
from ayran.context.ids import DEFAULT_CLUSTER_ID, ZERO_HASH
from ayran.context.lenses import LENS_NAMES
from ayran.context.queries import OntologyQueries, snapshot_view
from ayran.context.serialize import serialize_injection
from ayran.mapping import MAP_BUILDERS
from ayran.mapping.coverage import grid_from_cells, parse_cell_meta
from ayran.router.engine import RouterConfig, RouterEngine
from ayran.router.persist import (
    persist_coverage_cells,
    persist_graph_objects,
    persist_lens_state,
    persist_router_actions,
    persist_router_runtime,
)


def compile_pack(
    store: Any,
    *,
    cluster_id: str | None = None,
    token_budget: int = 4000,
    purpose: str = "audit-turn",
    role: str = "root-auditor",
    knowledge_policy: str | None = None,
    included_roots: list[str] | None = None,
    scope_id: str | None = None,
) -> dict[str, Any]:
    queries = OntologyQueries(store=store)
    view = snapshot_view(
        queries,
        cluster_id=cluster_id or DEFAULT_CLUSTER_ID,
        run_id=str(store.stream.get("run_id") or ""),
    )
    view.token_budget = token_budget
    view.purpose = purpose
    view.role = role
    if knowledge_policy:
        view.knowledge_policy = knowledge_policy
    if included_roots:
        view.included_roots = list(included_roots)
    if scope_id:
        view.scope_id = scope_id
    compiled = compile_with_injection(view, token_budget=token_budget, purpose=purpose, role=role)
    compiled["schema_version"] = "1.0.0"
    compiled["injection_text"] = compiled.get("injection_text") or serialize_injection(compiled["pack"])
    return compiled


def router_status(store: Any, *, cluster_id: str | None = None) -> dict[str, Any]:
    engine = RouterEngine()
    view = snapshot_view(
        OntologyQueries(store=store),
        cluster_id=cluster_id or DEFAULT_CLUSTER_ID,
        run_id=str(store.stream.get("run_id") or ""),
    )
    engine.restore(view)
    grid = grid_from_cells(view.cluster_id, view.coverage_cells)
    return {
        "schema_version": "1.0.0",
        "run_id": view.run_id,
        "cluster_id": view.cluster_id,
        "manual_next": engine.manual_next,
        "halted": engine.halted,
        "budget": engine.budget.as_dict(),
        "lens_states": {
            name: {
                "killed": name in engine.killed,
                "no_progress": engine.kill_streaks.get(name, 0),
                "spend": engine.budget.spent.get(name, 0),
            }
            for name in LENS_NAMES
        },
        "pending_actions": len(view.router_actions),
        "coverage": grid.get_coverage_summary(),
        "history_count": len(view.router_actions),
    }


def router_step(store: Any, *, cluster_id: str | None = None, persist: bool = True) -> dict[str, Any]:
    view = snapshot_view(
        OntologyQueries(store=store),
        cluster_id=cluster_id or DEFAULT_CLUSTER_ID,
        run_id=str(store.stream.get("run_id") or ""),
    )
    engine = RouterEngine(RouterConfig(created_at=view.created_at))
    result = engine.step(view)
    if persist:
        persist_router_actions(store, result.actions)
        persist_lens_state(store, result.lens_updates)
        persist_router_runtime(
            store,
            cluster_id=view.cluster_id,
            run_id=view.run_id,
            created_at=view.created_at,
            result=result,
            killed=engine.killed,
            kill_streaks=engine.kill_streaks,
            no_progress_cycles=engine.cycles_without_progress,
            freeze_hash=engine.anchoring.freeze_hashes.get(view.cluster_id) or ZERO_HASH,
            target_first_completed=bool(view.cluster_id in view.target_first_completed),
        )
    return {
        "schema_version": "1.0.0",
        "checksum": result.checksum,
        "manual_next": result.manual_next,
        "halted": result.halted,
        "reason": result.reason,
        "budget": result.budget,
        "anchoring_metrics": result.anchoring_metrics,
        "actions": result.actions,
        "lens_updates": result.lens_updates,
    }


def router_history(store: Any, *, limit: int = 20) -> dict[str, Any]:
    view = snapshot_view(OntologyQueries(store=store), run_id=str(store.stream.get("run_id") or ""))
    items = sorted(view.router_actions, key=lambda row: str(row.get("created_at") or ""))
    sliced = items[-max(1, min(limit, 200)) :]
    return {
        "schema_version": "1.0.0",
        "count": len(sliced),
        "actions": [
            {
                "router_action_id": item.get("router_action_id"),
                "handler": item.get("handler"),
                "priority": item.get("priority"),
                "status": item.get("status"),
                "stop_condition": item.get("stop_condition"),
                "deduplication_key": item.get("deduplication_key"),
            }
            for item in sliced
        ],
    }


def coverage_summary(store: Any, *, cluster_id: str | None = None) -> dict[str, Any]:
    view = snapshot_view(
        OntologyQueries(store=store),
        cluster_id=cluster_id or DEFAULT_CLUSTER_ID,
        run_id=str(store.stream.get("run_id") or ""),
    )
    grid = grid_from_cells(view.cluster_id, view.coverage_cells)
    return {"schema_version": "1.0.0", **grid.get_coverage_summary(), "cells": list(grid.cells.values())}


def coverage_cell(store: Any, cell_id: str) -> dict[str, Any]:
    view = snapshot_view(OntologyQueries(store=store), run_id=str(store.stream.get("run_id") or ""))
    for cell in view.coverage_cells:
        if cell.get("coverage_cell_id") == cell_id:
            meta = parse_cell_meta(str(cell.get("examined_result") or ""))
            return {"schema_version": "1.0.0", "cell": cell, "cell_state": meta.cell_state, "risk_score": meta.risk_score}
    return {"schema_version": "1.0.0", "cell": None, "error": "not_found"}


def build_maps(
    store: Any,
    map_type: str,
    *,
    cluster_id: str | None = None,
    source_text: str | None = None,
    slither_json: dict[str, Any] | None = None,
    solc_json: dict[str, Any] | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    builder = MAP_BUILDERS.get(map_type)
    if builder is None:
        raise LookupError(map_type)
    cluster = cluster_id or DEFAULT_CLUSTER_ID
    run_id = str(store.stream.get("run_id") or "")
    kwargs: dict[str, Any] = {
        "cluster_id": cluster,
        "run_id": run_id,
        "source_text": source_text,
        "slither_json": slither_json,
    }
    if map_type == "attack_surface":
        kwargs["solc_json"] = solc_json
    built = builder(**kwargs)
    if persist:
        persist_graph_objects(store, built.get("nodes") or [], built.get("edges") or [])
        if map_type == "attack_surface":
            from ayran.mapping.coverage import seed_grid_from_subjects

            subjects = {
                "entry_points": [item["name"] for item in built.get("entry_points") or []],
                "state_variables": [item["name"] for item in built.get("state_variables") or []],
                "invariants": ["conservation"],
                "external_interactions": [],
                "temporal_behaviors": [],
                "value_flows": [item["name"] for item in built.get("entry_points") or [] if item.get("payable") or item.get("value_flow")],
                "integration_boundaries": [],
            }
            grid = seed_grid_from_subjects(cluster, subjects, run_id=run_id, created_at="2026-08-12T12:00:00Z")
            persist_coverage_cells(store, list(grid.cells.values()))
    return {
        "schema_version": "1.0.0",
        "map_type": map_type,
        "cluster_id": cluster,
        "payload": built.get("payload") or {},
        "node_count": len(built.get("nodes") or []),
        "edge_count": len(built.get("edges") or []),
        "nodes": built.get("nodes") or [],
        "edges": built.get("edges") or [],
    }


def get_map(store: Any, map_type: str, *, cluster_id: str | None = None) -> dict[str, Any]:
    view = snapshot_view(
        OntologyQueries(store=store),
        cluster_id=cluster_id or DEFAULT_CLUSTER_ID,
        run_id=str(store.stream.get("run_id") or ""),
    )
    payload = view.maps.get(map_type) or {}
    return {"schema_version": "1.0.0", "map_type": map_type, "payload": payload, "present": bool(payload)}
