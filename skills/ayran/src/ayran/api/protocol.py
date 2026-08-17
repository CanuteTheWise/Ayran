"""JSON-RPC 2.0 wire protocol over a local Unix-domain stream socket.

Every frame is newline-delimited canonical JSON.  The owner-only socket checks
the connecting peer's UID with ``SO_PEERCRED`` and, when a run token has been
provided, requires the presented bearer in the params to match (constant time)
— the bearer itself MUST NOT appear as plaintext in an environment variable.
Authentication failure maps to one stable ``PERMISSION_DENIED`` code and no
response body carries the secret.
"""

from __future__ import annotations

import json
from typing import Any

from ayran.graph.canonical import strict_json_loads

# JSON-RPC 2.0 standard errors plus Ayran's stable wire codes from §3.7.
PARSE_ERROR = {"code": -32700, "message": "parse error"}
INVALID_REQUEST = {"code": -32600, "message": "invalid request"}
METHOD_NOT_FOUND = {"code": -32601, "message": "method not found"}
INVALID_PARAMS = {"code": -32602, "message": "invalid params"}
INTERNAL_ERROR = {"code": -32603, "message": "internal error"}

AUTHENTICATION_REQUIRED = {
    "code": -32001,
    "message": "authentication required",
    "retryable": False,
    "details": {"code": "PERMISSION_DENIED"},
}
STORE_BUSY = {
    "code": -32002,
    "message": "store busy",
    "retryable": True,
    "details": {"code": "STORE_BUSY"},
}
BUDGET_EXHAUSTED = {
    "code": -32003,
    "message": "budget exhausted",
    "retryable": True,
    "details": {"code": "BUDGET_EXHAUSTED"},
}
POLICY_DENIED = {
    "code": -32004,
    "message": "policy denied",
    "retryable": False,
    "details": {"code": "POLICY_DENIED"},
}


class ProtocolError(ValueError):
    def __init__(self, error: dict[str, Any]) -> None:
        self.error = error
        super().__init__(str(error))


def encode_request(method: str, params: dict[str, Any], *, request_id: Any = None) -> bytes:
    frame = {"jsonrpc": "2.0", "method": method, "params": params}
    if request_id is not None:
        frame["id"] = request_id
    return json.dumps(frame, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def encode_result(result: Any, request_id: Any) -> bytes:
    frame = {"jsonrpc": "2.0", "result": result, "id": request_id}
    return json.dumps(frame, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def encode_error(error: dict[str, Any], request_id: Any) -> bytes:
    frame = {"jsonrpc": "2.0", "error": error, "id": request_id}
    return json.dumps(frame, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def parse_frame(raw: bytes) -> Any:
    """Parse one request/response frame while rejecting duplicate keys and BOMs."""

    return strict_json_loads(raw.rstrip(b"\n"))

