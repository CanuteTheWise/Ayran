"""Stable, machine-actionable error taxonomy for the M2 local service.

Wire errors keep one canonical JSON-RPC shape (§3.7):
``{code, message, retryable, details, correlation_id}``.  The Python-side
exception preserves the stable code string while ``as_error_object`` renders
the wire object.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Blueprint §15 error taxonomy classes — stable and operator-actionable.
ERROR_TAXONOMY: dict[str, str] = {
    "CONFIG": "configuration input is invalid or inconsistent",
    "COMPATIBILITY": "Prime/tool/platform fact is outside the locked compatibility envelope",
    "POLICY": "monotonic policy was violated",
    "SCOPE": "a scope manifest check denied the action",
    "PERMISSION": "action is not authorized by the active runtime policy",
    "RESOURCE": "CPU/memory/disk/process budget is exhausted or unavailable",
    "DEPENDENCY": "required tool/library is absent or at the wrong version",
    "TOOL": "an external tool exited abnormally",
    "COMPILER": "target compiler/remapping failure",
    "RPC": "an allowlisted RPC endpoint failed",
    "GRAPH": "graph journal or projection failure",
    "CORRUPTION": "journal, projection, artifact, or receipt integrity failure",
    "CONTEXT": "context compilation failure",
    "MODEL": "model provider failure",
    "PROOF": "executable proof failure",
    "REPORT": "report rendering failure",
    "INTERNAL": "unexpected invariant break; never means an audit action succeeded",
}

RETRY_CLASSES = ("never", "bounded", "after_change")


@dataclass(slots=True)
class ServiceError(RuntimeError):
    """Operator-safe failure with stable code, retry class, and causal context."""

    taxonomy: str
    code: str
    message: str
    retryable: bool = False
    retry_class: str = "never"
    details: dict[str, Any] | None = None
    cause_id: str | None = None

    def __post_init__(self) -> None:
        RuntimeError.__init__(self, self.message)
        if self.taxonomy not in ERROR_TAXONOMY:
            self.taxonomy = "INTERNAL"
        if self.retry_class not in RETRY_CLASSES:
            self.retry_class = "never"

    def as_error_object(self, correlation_id: str) -> dict[str, Any]:
        value: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "details": {
                "taxonomy": self.taxonomy,
                "retry_class": self.retry_class,
                **(self.details or {}),
            },
            "correlation_id": correlation_id,
        }
        if self.cause_id:
            value["details"]["cause_id"] = self.cause_id
        return value


def internal(code: str, message: str, *, details: dict[str, Any] | None = None) -> ServiceError:
    return ServiceError("INTERNAL", code, message, details=details)

