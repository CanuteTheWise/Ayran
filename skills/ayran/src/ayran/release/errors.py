"""Distribution and release failures with stable machine codes."""

from __future__ import annotations

from typing import Any

from ayran.graph.errors import GraphError

URL_CLOSURE_INCOMPLETE = "URL_CLOSURE_INCOMPLETE"
BUNDLE_INVALID = "BUNDLE_INVALID"
RECEIPT_INVALID = "RECEIPT_INVALID"
INSTALL_REFUSED = "INSTALL_REFUSED"
ROLLBACK_DENIED = "ROLLBACK_DENIED"
SIGNATURE_MISMATCH = "SIGNATURE_MISMATCH"
PRIME_EXTERNAL_PROTECTED = "PRIME_EXTERNAL_PROTECTED"


class ReleaseError(GraphError):
    """Operator-safe release/install failure. Never mutates externally owned Prime."""

    def as_result(self) -> dict[str, Any]:
        return {"accepted": False, "error": self.as_dict()}
