"""Learning-plane failures with stable machine codes."""

from __future__ import annotations

from typing import Any

from ayran.graph.errors import GraphError

PROMOTION_DENIED = "PROMOTION_DENIED"
QUARANTINE_REQUIRED = "QUARANTINE_REQUIRED"
CONTAMINATION_BLOCKED = "CONTAMINATION_BLOCKED"
REVIEW_INCOMPLETE = "REVIEW_INCOMPLETE"
REDACTION_INCOMPLETE = "REDACTION_INCOMPLETE"
ABLATION_FAILED = "ABLATION_FAILED"
SECRET_EXCLUDED = "SECRET_EXCLUDED"
LEARNING_NOT_FOUND = "LEARNING_NOT_FOUND"
RELEASE_UNAVAILABLE = "RELEASE_UNAVAILABLE"
DIRECT_MUTATION_DENIED = "DIRECT_MUTATION_DENIED"
FIXTURES_REQUIRED = "FIXTURES_REQUIRED"
TTL_EXPIRED = "TTL_EXPIRED"


class LearningError(GraphError):
    """Operator-safe learning failure; never mutates Global production."""

    def as_result(self) -> dict[str, Any]:
        return {"accepted": False, "error": self.as_dict()}
