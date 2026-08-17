"""Typed in-process command surface for the M1 Graph Fabric."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

TransitionKind = Literal["snapshot", "retraction", "tombstone"]


@dataclass(frozen=True, slots=True)
class AppendItem:
    contract_id: str
    event_type: str
    value: dict[str, Any]
    aggregate_id: str | None = None
    transition: TransitionKind = "snapshot"
    reason: str | None = None
    supersedes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AppendCommand:
    idempotency_key: str
    items: tuple[AppendItem, ...]
    expected_revisions: dict[str, int]
    actor: dict[str, Any]
    config_hash: str
    source_version: str
    operation_id: str | None = None
    causation_id: str | None = None
    created_at: str | None = None


@dataclass(slots=True)
class VerificationState:
    cursor: int = 0
    last_event_hash: str | None = None
    last_commit_hash: str | None = None
    batch_count: int = 0
    event_count: int = 0
    segment_count: int = 0
    committed_batches: list[tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]] = field(
        default_factory=list
    )
    issues: list[dict[str, Any]] = field(default_factory=list)
    recovered_suffix_hash: str | None = None

