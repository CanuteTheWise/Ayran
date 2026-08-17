"""Sealed evaluation failures with stable machine codes."""

from __future__ import annotations

from typing import Any

from ayran.graph.errors import GraphError

SEALED_LEAKAGE = "SEALED_LEAKAGE"
EVALUATION_INVALID = "EVALUATION_INVALID"
ARM_UNKNOWN = "ARM_UNKNOWN"
SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
MANIFEST_IMMUTABLE = "MANIFEST_IMMUTABLE"
HOLD_OUT_UNAVAILABLE = "HOLD_OUT_UNAVAILABLE"
SEED_REQUIRED = "SEED_REQUIRED"


class EvaluationError(GraphError):
    """Operator-safe evaluation failure; never mutates Global or Learning production."""

    def as_result(self) -> dict[str, Any]:
        return {"accepted": False, "error": self.as_dict()}
