"""Stable tool-adapter errors.  Codes are operator-safe and contain no secrets."""

from __future__ import annotations

from ayran.graph.errors import GraphError

UNAVAILABLE = "TOOL_UNAVAILABLE"
PARSER_FAILED = "PARSER_FAILED"
TIMEOUT = "TOOL_TIMEOUT"
POLICY_DENIED = "POLICY_DENIED"
INSTALL_DISABLED = "INSTALL_DISABLED"
PRIVACY_REJECTED = "PRIVACY_REJECTED"
SYMLINK_ESCAPE = "SYMLINK_ESCAPE"
OUTPUT_TRUNCATED = "OUTPUT_TRUNCATED"


class ToolError(GraphError):
    """Fail-closed adapter, registry, or runner error."""
