"""Initial journal-v1 to projection-v1 migration."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class InitialMigration:
    version: int = 1
    name: str = "initial_projection_v1"

    def precheck(self, source_version: int) -> None:
        if source_version not in {0, 1}:
            raise ValueError("migration 1 accepts only an empty or v1 projection")

    def apply_event_transform(self, event: Mapping[str, Any]) -> Mapping[str, Any]:
        if event.get("journal_format_version") != 1:
            raise ValueError("migration 1 accepts journal format v1 only")
        return event

    def rebuild_projection(
        self,
        destination: Path,
        batches: Iterable[tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]],
        rebuild: Callable[
            [Path, Iterable[tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]]], None
        ],
    ) -> None:
        rebuild(destination, batches)

    def validate(self, integrity_result: tuple[bool, list[str]]) -> None:
        ok, issues = integrity_result
        if not ok:
            raise ValueError("migration validation failed: " + "; ".join(issues))


MIGRATION = InitialMigration()

