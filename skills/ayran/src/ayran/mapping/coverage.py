"""Risk-weighted coverage grid with forward-only cell transitions."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from ayran.context.contracts import default_target_identity, provenance_record
from ayran.context.ids import DEFAULT_CLUSTER_ID, DEFAULT_RUN_ID, ZERO_HASH, content_id
from ayran.graph.canonical import object_hash

CellState = Literal[
    "unexamined",
    "in_progress",
    "examined_no_issue",
    "blocked",
    "lead_found",
    "hypothesis_active",
    "validated",
    "residual_risk",
]

DIMENSIONS = (
    "entry_points",
    "state_variables",
    "invariants",
    "external_interactions",
    "temporal_behaviors",
    "value_flows",
    "integration_boundaries",
)

CELL_RANK: dict[str, int] = {
    "unexamined": 0,
    "in_progress": 1,
    "examined_no_issue": 2,
    "lead_found": 3,
    "hypothesis_active": 4,
    "validated": 5,
    "blocked": 5,
    "residual_risk": 5,
}

STATE_TO_SCHEMA: dict[str, tuple[str, str]] = {
    "unexamined": ("open", "inventory"),
    "in_progress": ("open", "reviewed"),
    "examined_no_issue": ("examined", "reviewed"),
    "blocked": ("blocked", "blocked"),
    "lead_found": ("open", "reviewed"),
    "hypothesis_active": ("open", "tested"),
    "validated": ("examined", "tested"),
    "residual_risk": ("accepted_residual_risk", "reviewed"),
}

_META = re.compile(r"^\[([a-z_]+)(?:\|risk=(\d+))?\]\s*")


@dataclass(frozen=True, slots=True)
class CellMeta:
    cell_state: CellState
    risk_score: int
    narrative: str


def parse_cell_meta(examined_result: str) -> CellMeta:
    match = _META.match(examined_result)
    if not match:
        return CellMeta("unexamined", 0, examined_result)
    state = match.group(1)
    if state not in CELL_RANK:
        state = "unexamined"
    risk = int(match.group(2) or 0)
    return CellMeta(state, risk, examined_result[match.end() :])  # type: ignore[arg-type]


def format_cell_meta(state: CellState, risk_score: int, narrative: str) -> str:
    body = narrative.strip() or "cell recorded"
    text = f"[{state}|risk={int(risk_score)}] {body}"
    return text[:2048]


def risk_score(
    *,
    value_at_risk: int = 0,
    privilege_level: int = 0,
    external_interactions: int = 0,
    historical_precedent: int = 0,
) -> int:
    return (
        max(0, int(value_at_risk)) * 10
        + max(0, int(privilege_level)) * 5
        + max(0, int(external_interactions)) * 3
        + max(0, int(historical_precedent)) * 2
    )


class CoverageTransitionError(ValueError):
    """Raised when a backward cell transition is attempted without invalidation."""


@dataclass(slots=True)
class CoverageGrid:
    cluster_id: str = DEFAULT_CLUSTER_ID
    cells: dict[str, dict[str, Any]] = field(default_factory=dict)

    def cell_id(self, dimension: str, subject: str) -> str:
        return content_id("cov", self.cluster_id, dimension, subject)

    def get(self, dimension: str, subject: str) -> dict[str, Any] | None:
        return self.cells.get(self.cell_id(dimension, subject))

    def ensure(
        self,
        dimension: str,
        subject: str,
        *,
        run_id: str = DEFAULT_RUN_ID,
        target_identity: dict[str, Any] | None = None,
        risk: int = 0,
        created_at: str = "2026-08-12T12:00:00Z",
        target_refs: list[str] | None = None,
    ) -> dict[str, Any]:
        identifier = self.cell_id(dimension, subject)
        existing = self.cells.get(identifier)
        if existing is not None:
            return existing
        cell = coverage_cell_record(
            coverage_cell_id=identifier,
            dimension=f"{dimension}:{subject}",
            cell_state="unexamined",
            risk_score=risk,
            run_id=run_id,
            target_identity=target_identity,
            created_at=created_at,
            target_refs=target_refs or [],
            narrative=f"unexamined {dimension} {subject}",
        )
        self.cells[identifier] = cell
        return cell

    def transition(
        self,
        dimension: str,
        subject: str,
        new_state: CellState,
        *,
        invalidate: bool = False,
        narrative: str | None = None,
        evidence_ref: str | None = None,
        updated_at: str = "2026-08-12T12:00:00Z",
    ) -> dict[str, Any]:
        cell = self.ensure(dimension, subject)
        meta = parse_cell_meta(str(cell.get("examined_result") or ""))
        old_rank = CELL_RANK[meta.cell_state]
        new_rank = CELL_RANK[new_state]
        if new_rank < old_rank and not invalidate:
            raise CoverageTransitionError(
                f"backward coverage transition {meta.cell_state} -> {new_state} requires invalidation"
            )
        schema_status, depth = STATE_TO_SCHEMA[new_state]
        cell["status"] = schema_status
        cell["depth"] = depth
        cell["updated_at"] = updated_at
        cell["examined_result"] = format_cell_meta(
            new_state, meta.risk_score, narrative or meta.narrative or new_state
        )
        if evidence_ref:
            refs = list(cell.get("target_refs") or [])
            if evidence_ref not in refs:
                refs.append(evidence_ref)
            cell["target_refs"] = refs[:256]
        cell["integrity"] = {
            "algorithm": "sha256",
            "canonicalization": "rfc8785",
            "content_hash": ZERO_HASH,
            "excluded_fields": ["integrity.content_hash"],
        }
        cell["integrity"]["content_hash"] = object_hash(cell)
        self.cells[cell["coverage_cell_id"]] = cell
        return cell

    def get_risk_weighted_uncovered(self, threshold: int = 0) -> list[dict[str, Any]]:
        uncovered: list[dict[str, Any]] = []
        for cell in self.cells.values():
            meta = parse_cell_meta(str(cell.get("examined_result") or ""))
            if (
                meta.cell_state in {"unexamined", "in_progress", "lead_found", "hypothesis_active"}
                and meta.risk_score >= threshold
            ):
                uncovered.append(cell)
        return sorted(
            uncovered,
            key=lambda row: (
                -parse_cell_meta(str(row.get("examined_result") or "")).risk_score,
                str(row.get("coverage_cell_id")),
            ),
        )

    def get_coverage_summary(self) -> dict[str, Any]:
        counts = {state: 0 for state in CELL_RANK}
        blocked = 0
        remaining_risk = 0
        for cell in self.cells.values():
            meta = parse_cell_meta(str(cell.get("examined_result") or ""))
            counts[meta.cell_state] = counts.get(meta.cell_state, 0) + 1
            if meta.cell_state == "blocked" or cell.get("status") == "blocked":
                blocked += 1
            if meta.cell_state in {"unexamined", "in_progress", "lead_found", "hypothesis_active"}:
                remaining_risk += meta.risk_score
        return {
            "cluster_id": self.cluster_id,
            "cell_count": len(self.cells),
            "by_state": counts,
            "cells_blocked": blocked,
            "remaining_risk": remaining_risk,
            "cells_examined": counts["examined_no_issue"] + counts["validated"] + counts["residual_risk"],
        }

    def get_stale_cells(self, ttl: str, now: str) -> list[dict[str, Any]]:
        """Return cells whose updated_at is older than ttl timestamp (string compare)."""

        _ = ttl
        stale = [
            cell
            for cell in self.cells.values()
            if str(cell.get("updated_at") or "") < now
            and parse_cell_meta(str(cell.get("examined_result") or "")).cell_state == "in_progress"
        ]
        return sorted(stale, key=lambda row: str(row.get("coverage_cell_id")))


def coverage_cell_record(
    *,
    coverage_cell_id: str,
    dimension: str,
    cell_state: CellState,
    risk_score: int,
    run_id: str,
    created_at: str,
    target_identity: dict[str, Any] | None = None,
    target_refs: list[str] | None = None,
    narrative: str = "cell recorded",
    attempted_origins: list[str] | None = None,
) -> dict[str, Any]:
    status, depth = STATE_TO_SCHEMA[cell_state]
    identity = target_identity or default_target_identity()
    value: dict[str, Any] = {
        "schema_version": "1.0.0",
        "coverage_cell_id": coverage_cell_id,
        "created_at": created_at,
        "run_id": run_id,
        "target_identity": identity,
        "dimension": dimension[:256],
        "target_refs": target_refs or [],
        "invariant_ids": [],
        "entry_point_ids": [],
        "attempted_origins": attempted_origins or [],
        "attempted_tools": [],
        "depth": depth,
        "achieved_evidence_grade": "lead",
        "status": status,
        "examined_result": format_cell_meta(cell_state, risk_score, narrative),
        "gaps": ["untried sibling paths"] if cell_state in {"unexamined", "in_progress"} else [],
        "blockers": ["missing fact"] if cell_state == "blocked" else [],
        "untried_dimensions": [] if cell_state in {"validated", "residual_risk"} else [dimension],
        "updated_at": created_at,
        "provenance": [provenance_record(created_at=created_at, material=coverage_cell_id)],
        "integrity": {
            "algorithm": "sha256",
            "canonicalization": "rfc8785",
            "content_hash": ZERO_HASH,
            "excluded_fields": ["integrity.content_hash"],
        },
    }
    value["integrity"]["content_hash"] = object_hash(value)
    return value


def grid_from_cells(cluster_id: str, cells: list[dict[str, Any]]) -> CoverageGrid:
    grid = CoverageGrid(cluster_id=cluster_id)
    for cell in cells:
        identifier = str(cell.get("coverage_cell_id") or "")
        if identifier:
            grid.cells[identifier] = cell
    return grid


def seed_grid_from_subjects(
    cluster_id: str,
    subjects_by_dimension: dict[str, list[str]],
    *,
    run_id: str,
    created_at: str,
    value_at_risk: int = 5,
    privilege_level: int = 1,
    external_interactions: int = 0,
    target_identity: dict[str, Any] | None = None,
) -> CoverageGrid:
    grid = CoverageGrid(cluster_id=cluster_id)
    score = risk_score(
        value_at_risk=value_at_risk,
        privilege_level=privilege_level,
        external_interactions=external_interactions,
    )
    for dimension in DIMENSIONS:
        for subject in sorted(subjects_by_dimension.get(dimension, [])):
            grid.ensure(
                dimension,
                subject,
                run_id=run_id,
                created_at=created_at,
                risk=score,
                target_refs=[cluster_id],
                target_identity=target_identity,
            )
    return grid
