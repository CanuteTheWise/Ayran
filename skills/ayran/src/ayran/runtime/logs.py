"""Structured JSON logging with mandatory redaction before persistence.

Every emitted record is one canonical JSON object as required by blueprint
§15.  Secrets, raw credentials and payload bodies must never reach durable
logs; this module enforces a deny-by-default redaction of values whose keys
are known-safe.  Authoritative logs live under the run root on WSL ext4
(never DrvFS) via one fsync-per-record append.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ayran.graph.canonical import canonical_bytes, fsync_directory, utc_now, write_all
from ayran.graph.ids import new_id

LEVELS = ("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL")

# Exact key names whose values may persist.  Everything else, including nested
# mappings and lists, is redacted unless explicitly allowlisted.  This is the
# deny-by-default half of redaction-before-persistence.
SAFE_DETAIL_KEYS = frozenset(
    {
        "code",
        "component",
        "operation",
        "outcome",
        "duration_ms",
        "retry_count",
        "attempt",
        "max_attempts",
        "exit_code",
        "signal",
        "signal_name",
        "terminated_by",
        "pid",
        "process_uid",
        "pgid",
        "cursor",
        "seq",
        "batch_id",
        "event_count",
        "content_hash",
        "artifact_digest",
        "chunk_count",
        "bytes",
        "size",
        "path_role",
        "root",
        "scope_decision",
        "action",
        "policy",
        "count",
        "revision",
        "expected_revision",
        "current_revision",
        "state",
        "transition",
        "reason_code",
        "allowed_roots",
        "denied_patterns",
        "filesystem",
        "release_id",
        "run_state",
        "method",
        "request_id",
        "correlation_id",
        "error_class",
        "message",
        "retryable",
    }
)
REDACTED = "[REDACTED]"

# Additional textual secrets that are scrubbed inside otherwise-safe strings.
_SECRET_TEMPLATE_MARKERS = ("akia", "-----begin", "x-api-key:", "authorization: bearer", "private_key")


def _redact_string(value: str) -> str:
    lowered = value.lower()
    for marker in _SECRET_TEMPLATE_MARKERS:
        if marker in lowered:
            return REDACTED
    if len(value) > 4096:
        return value[:4096] + "...[truncated]"
    return value


def _redact(value: Any, path: str) -> Any:
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            child = f"{path}.{key_str}" if path else key_str
            if key_str not in SAFE_DETAIL_KEYS:
                out[key_str] = REDACTED
            else:
                out[key_str] = _redact(item, child)
        return out
    if isinstance(value, (list, tuple)):
        # List contents are untrusted unless the key itself was allowlisted,
        # and safe scalar values pass through the mapping branch.  Persisting
        # whole lists risks unredacted payloads, so they collapse.
        return REDACTED
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return REDACTED


class StructuredLogger:
    """Append one fsync'd canonical JSON log record per event to a run log."""

    def __init__(
        self,
        root: Path,
        *,
        run_id: str,
        engagement_id: str | None = None,
        component: str,
        level: str = "INFO",
    ) -> None:
        self.path = Path(root)
        self.run_id = run_id
        self.engagement_id = engagement_id
        self.component = component
        self.level = level
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _emit(self, level: str, event_type: str, operation_id: str, detail: Mapping[str, Any]) -> dict[str, Any]:
        record: dict[str, Any] = {
            "schema_version": "1.0.0",
            "record_id": new_id("log"),
            "timestamp": utc_now(),
            "level": level,
            "event_type": event_type,
            "run_id": self.run_id,
            "engagement_id": self.engagement_id,
            "component": self.component,
            "operation_id": operation_id,
            "detail": _redact(dict(detail), ""),
        }
        line = canonical_bytes(record) + b"\n"
        fd = os.open(
            self.path,
            os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            write_all(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        fsync_directory(self.path.parent)
        return record

    def event(self, level: str, event_type: str, *, operation_id: str | None = None, **detail: Any) -> dict[str, Any]:
        if level not in LEVELS:
            raise ValueError(f"unknown log level: {level}")
        return self._emit(level, event_type, operation_id or new_id("op"), detail)

    def error(self, event_type: str, error: BaseException, *, operation_id: str | None = None, **detail: Any) -> dict[str, Any]:
        """Log an exception without persisting raw tracebacks or secret bodies.

        The exception class and a truncated message are kept; frame locals and
        attached payloads are never persisted.
        """

        safe = {
            "error_class": type(error).__name__,
            "message": str(error)[:512],
        }
        safe.update(detail)
        return self._emit("ERROR", event_type, operation_id or new_id("op"), safe)

