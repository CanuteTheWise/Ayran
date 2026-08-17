"""Knowledge-plane failures with stable machine codes."""

from __future__ import annotations

from typing import Any

from ayran.graph.errors import GraphError

SOURCE_NOT_FOUND = "SOURCE_NOT_FOUND"
SOURCE_DEFERRED = "SOURCE_DEFERRED"
SOURCE_TOMBSTONED = "SOURCE_TOMBSTONED"
INGESTION_QUARANTINED = "INGESTION_QUARANTINED"
CORPUS_UNAVAILABLE = "CORPUS_UNAVAILABLE"
LICENSE_INCOMPLETE = "LICENSE_INCOMPLETE"
CONTAMINATION_BLOCKED = "CONTAMINATION_BLOCKED"
NETWORK_FORBIDDEN = "NETWORK_FORBIDDEN"


class KnowledgeError(GraphError):
    """Operator-safe knowledge failure; never mutates journal state."""

    def as_result(self) -> dict[str, Any]:
        return {"accepted": False, "error": self.as_dict()}
