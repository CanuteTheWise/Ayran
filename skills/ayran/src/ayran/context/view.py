"""In-memory Target/Global/Learning snapshot consumed by the compiler and router."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ayran.context.ids import DEFAULT_CLUSTER_ID, DEFAULT_RUN_ID, ZERO_HASH, content_id
from ayran.graph.canonical import canonical_hash


@dataclass(slots=True)
class GraphView:
    """Deterministic graph snapshot. Drivers and the compiler never open SQLite."""

    run_id: str = DEFAULT_RUN_ID
    target_identity: dict[str, Any] = field(default_factory=dict)
    cluster_id: str = DEFAULT_CLUSTER_ID
    phase: str = "map"
    cursor: int = 0
    event_hash: str = ZERO_HASH
    token_budget: int = 4000
    knowledge_policy: str = "target_only"
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    coverage_cells: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    tool_runs: list[dict[str, Any]] = field(default_factory=list)
    dead_ends: list[dict[str, Any]] = field(default_factory=list)
    open_questions: list[dict[str, Any]] = field(default_factory=list)
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    maps: dict[str, dict[str, Any]] = field(default_factory=dict)
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    source_units: list[dict[str, Any]] = field(default_factory=list)
    global_mechanisms: list[dict[str, Any]] = field(default_factory=list)
    global_incidents: list[dict[str, Any]] = field(default_factory=list)
    global_patterns: list[dict[str, Any]] = field(default_factory=list)
    router_actions: list[dict[str, Any]] = field(default_factory=list)
    driver_states: dict[str, dict[str, Any]] = field(default_factory=dict)
    budget_state: dict[str, Any] = field(default_factory=dict)
    freeze_snapshots: dict[str, str] = field(default_factory=dict)
    payload_strikes: dict[str, int] = field(default_factory=dict)
    quarantined_sources: list[str] = field(default_factory=list)
    policy_constraints: list[str] = field(default_factory=list)
    high_value_clusters: list[str] = field(default_factory=list)
    target_first_completed: list[str] = field(default_factory=list)
    tool_health: dict[str, str] = field(default_factory=dict)
    created_at: str = "2026-08-12T12:00:00Z"
    policy_checksum: str = ZERO_HASH
    config_checksum: str = ZERO_HASH
    scope_id: str = "scp_01J00000000000000000000001"
    purpose: str = "audit-turn"
    role: str = "root-auditor"
    no_progress_cycles: int = 0
    manual_next: bool = False
    dual_review: bool = False
    value_at_risk: int = 50
    capabilities: list[dict[str, Any]] = field(default_factory=list)

    def snapshot_hash(self) -> str:
        return canonical_hash(
            {
                "cluster_id": self.cluster_id,
                "cursor": self.cursor,
                "event_hash": self.event_hash,
                "hypotheses": sorted(
                    (item.get("hypothesis_id"), item.get("claim"), item.get("origin"))
                    for item in self.hypotheses
                ),
                "coverage": sorted(
                    (item.get("coverage_cell_id"), item.get("status"), item.get("dimension"))
                    for item in self.coverage_cells
                ),
                "maps": sorted(self.maps),
                "knowledge_policy": self.knowledge_policy,
            }
        )


def reconstruction_fingerprint(view: GraphView) -> dict[str, str]:
    """Collapse reconstruction keys that must be recoverable from the graph alone."""

    active = [
        item
        for item in view.hypotheses
        if item.get("status")
        not in {"falsified", "parked", "duplicate_known_issue", "reported"}
    ]
    dead = [item for item in view.hypotheses if item.get("status") in {"falsified", "parked"}]
    untried = [
        item
        for item in view.coverage_cells
        if item.get("status") in {"open", None} or "unexamined" in str(item.get("examined_result") or "")
    ]
    next_action = "continue mapping"
    if active:
        next_action = "advance active hypotheses"
    elif untried:
        next_action = "cover untried dimensions"
    return {
        "active_hypothesis": canonical_hash(
            [(item.get("hypothesis_id"), item.get("claim"), item.get("origin")) for item in active]
        ),
        "result_so_far": canonical_hash(
            [(item.get("evidence_id"), item.get("evidence_grade")) for item in view.evidence]
        ),
        "next_action": content_id("nxt", next_action, view.cluster_id),
        "dead_approaches": canonical_hash(
            [(item.get("hypothesis_id"), item.get("claim")) for item in dead]
            + [(item.get("approach"), item.get("reason")) for item in view.dead_ends]
        ),
        "untried_dimensions": canonical_hash(
            [
                (item.get("coverage_cell_id"), item.get("dimension"), item.get("status"))
                for item in untried
            ]
        ),
    }
