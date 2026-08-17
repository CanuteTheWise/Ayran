"""Evidence-pipeline failures with stable machine codes."""

from __future__ import annotations

from typing import Any

from ayran.graph.errors import GraphError

TRANSITION_REJECTED = "TRANSITION_REJECTED"
UNAUTHORIZED_ACTOR = "UNAUTHORIZED_ACTOR"
MISSING_EVIDENCE = "MISSING_EVIDENCE"
EVIDENCE_CEILING = "EVIDENCE_CEILING"
HYPOTHESIS_NOT_FOUND = "HYPOTHESIS_NOT_FOUND"
FINDING_NOT_FOUND = "FINDING_NOT_FOUND"
POC_NOT_FOUND = "POC_NOT_FOUND"
GATE_PRECONDITION = "GATE_PRECONDITION"
REPORT_LINT_FAILED = "REPORT_LINT_FAILED"


class EvidenceError(GraphError):
    """Operator-safe evidence failure; never mutates journal state."""

    def as_result(self) -> dict[str, Any]:
        return {"accepted": False, "error": self.as_dict()}
