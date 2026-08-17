"""Stable, testable Graph Fabric errors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class GraphError(RuntimeError):
    """An operator-safe graph failure with a stable machine code."""

    code: str
    message: str
    retryable: bool = False
    details: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        RuntimeError.__init__(self, self.message)

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
        }
        if self.details:
            value["details"] = self.details
        return value


CONTRACT_INVALID = "CONTRACT_INVALID"
NAMESPACE_MISMATCH = "NAMESPACE_MISMATCH"
CONFLICT_REVISION = "CONFLICT_REVISION"
IDEMPOTENCY_COLLISION = "IDEMPOTENCY_COLLISION"
STORE_BUSY = "STORE_BUSY"
LEASE_HELD = "LEASE_HELD"
JOURNAL_CORRUPT = "JOURNAL_CORRUPT"
PROJECTION_CORRUPT = "PROJECTION_CORRUPT"
MIGRATION_REQUIRED = "MIGRATION_REQUIRED"
UNSUPPORTED_SCHEMA_VERSION = "UNSUPPORTED_SCHEMA_VERSION"
RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"

