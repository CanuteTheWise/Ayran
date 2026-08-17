"""Normalize truncated, gzipped, binary, and oversized tool output without crashing."""

from __future__ import annotations

import gzip
import zlib
from typing import Any

from ayran.tools.errors import PARSER_FAILED, ToolError
from ayran.tools.types import RawRun

GZIP_MAGIC = b"\x1f\x8b"
MAX_DECODE_BYTES = 8 * 1024 * 1024


def prepare_tool_output(raw: bytes, *, max_bytes: int = MAX_DECODE_BYTES) -> dict[str, Any]:
    kind = "utf8"
    payload = raw
    if len(payload) > max_bytes:
        payload = payload[:max_bytes]
        kind = "oversized"
    if payload.startswith(GZIP_MAGIC):
        try:
            payload = gzip.decompress(payload)
            kind = "gzip"
        except (OSError, EOFError, zlib.error):
            kind = "truncated_gzip"
            payload = b""
        if len(payload) > max_bytes:
            payload = payload[:max_bytes]
            kind = "gzip_oversized"
    if b"\x00" in payload[:1024]:
        kind = "binary"
        payload = b""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        text = payload.decode("utf-8", errors="replace")
        if kind == "utf8":
            kind = "lossy"
    return {"kind": kind, "text": text, "bytes": payload, "truncated": kind in {"oversized", "truncated_gzip", "gzip_oversized"}}


def parse_or_reject(raw: RawRun, parser: Any) -> Any:
    prepared = prepare_tool_output(raw.stdout)
    try:
        if prepared["kind"] in {"binary", "truncated_gzip"}:
            raise ToolError(PARSER_FAILED, f"malformed tool output ({prepared['kind']})")
        clone = RawRun(
            argv=raw.argv,
            cwd=raw.cwd,
            env_fingerprint=raw.env_fingerprint,
            started_at=raw.started_at,
            ended_at=raw.ended_at,
            exit_code=raw.exit_code,
            signal=raw.signal,
            stdout=prepared["bytes"],
            stderr=raw.stderr,
            stdout_truncated=raw.stdout_truncated or prepared["truncated"],
            stderr_truncated=raw.stderr_truncated,
            stdout_hash=raw.stdout_hash,
            stderr_hash=raw.stderr_hash,
            output_file_hashes=raw.output_file_hashes,
            input_hashes=raw.input_hashes,
            executable_hash=raw.executable_hash,
            timeout=raw.timeout,
            failure_type=raw.failure_type,
            extra=raw.extra,
        )
        return parser(clone)
    except ToolError:
        raise
    except Exception as error:
        raise ToolError(PARSER_FAILED, f"adapter crashed on malformed output: {error}") from error
