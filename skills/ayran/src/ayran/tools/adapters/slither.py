"""Slither 0.11.5 adapter.  Alerts are leads; compilation facts are observed."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

from ayran.tools.base import (
    ExecutableAdapter,
    _env_overlay,
    build_argv,
    file_sha256,
    filter_env,
    invoke_executable,
    mapping_of,
    resolve_executable,
    unique_hashes,
)
from ayran.tools.errors import PARSER_FAILED, ToolError
from ayran.tools.types import (
    ALIAS_SLITHER,
    ExecutionPolicy,
    RawRun,
    SlitherAlert,
    SlitherCompilationFact,
    SlitherRunRequest,
    SlitherRunResult,
    SlitherSpan,
)

_VERSION_RE = re.compile(r"([0-9]+\.[0-9]+\.[0-9]+)")
_VIEW_RE = re.compile(r"\b(view|pure)\b", re.IGNORECASE)
_REENTRANCY_RE = re.compile(r"reentrancy", re.IGNORECASE)


def parse_slither_version(text: str) -> str | None:
    match = _VERSION_RE.search(text.strip())
    return match.group(1) if match else None


def _spans_from_element(element: dict[str, Any]) -> list[SlitherSpan]:
    mapping = element.get("source_mapping")
    if not isinstance(mapping, dict):
        return []
    lines = mapping.get("lines")
    line = None
    if isinstance(lines, list) and lines:
        first = lines[0]
        line = int(first) if isinstance(first, int) else None
    file_name = str(
        mapping.get("filename_relative")
        or mapping.get("filename_short")
        or mapping.get("filename_absolute")
        or element.get("name")
        or "unknown"
    )
    column = mapping.get("starting_column")
    return [
        SlitherSpan(
            file=file_name,
            line=line,
            column=int(column) if isinstance(column, int) else None,
        )
    ]


def classify_alert(check: str, description: str) -> str:
    if (
        _REENTRANCY_RE.search(check) or _REENTRANCY_RE.search(description)
    ) and _VIEW_RE.search(description):
        return "known_false_positive_pattern"
    return "alert_lead"


class SlitherAdapter(ExecutableAdapter):
    alias = ALIAS_SLITHER
    request_type = SlitherRunRequest

    def parse_version(self, output: str) -> str | None:
        return parse_slither_version(output)

    def expected_upstream_version(self) -> str:
        return "0.11.5"

    async def run(self, request: SlitherRunRequest, policy: ExecutionPolicy) -> RawRun:  # type: ignore[override]
        invocation = mapping_of(self.manifest.get("invocation"))
        template = invocation.get("argv_template")
        if not isinstance(template, list):
            raise ToolError("CONTRACT_INVALID", "slither argv_template is missing")
        output_file = Path(request.output_file) if request.output_file else (
            Path(tempfile.mkdtemp(prefix="ayran-slither-")) / "report.json"
        )
        sources = [str(Path(item)) for item in request.source_paths]
        substitutions: dict[str, str | list[str]] = {
            "output_file": str(output_file),
            "source_paths": sources,
        }
        argv = build_argv([str(item) for item in template], substitutions)
        if request.detectors:
            argv.extend(["--detect", ",".join(request.detectors)])
        env = self.environment
        resolved = resolve_executable(argv[0], env=env, path_env=env.path)
        argv[0] = str(resolved)
        filtered = filter_env(None, extra_allowlist=self.extra_env_allowlist, overlay=_env_overlay(env))
        cwd = Path(request.target_root) if request.target_root else None
        raw = invoke_executable(
            argv,
            cwd=cwd,
            env=filtered,
            timeout_seconds=min(policy.timeout_seconds, self.timeout_seconds()),
            max_output_bytes=policy.max_output_bytes,
            graceful_stop_seconds=policy.graceful_stop_seconds,
            input_paths=[Path(item) for item in sources],
            extra_output_files=[output_file],
        )
        if output_file.is_file():
            raw.output_file_hashes[str(output_file)] = file_sha256(output_file)
            raw.extra["output_file"] = str(output_file)
        raw.input_hashes = unique_hashes(raw.input_hashes)
        stderr = raw.stderr.decode("utf-8", errors="replace")
        if raw.timeout:
            raw.failure_type = "timeout"
        elif "Compilation failed" in stderr or "CompilerError" in stderr:
            raw.failure_type = "compile"
        return raw

    def parse(self, raw: RawRun) -> SlitherRunResult:
        payload_text = raw.stdout.decode("utf-8", errors="replace").strip()
        output_file = raw.extra.get("output_file")
        if isinstance(output_file, str) and Path(output_file).is_file():
            payload_text = Path(output_file).read_text(encoding="utf-8", errors="replace")
        if not payload_text:
            if raw.exit_code == 0:
                raise ToolError(
                    PARSER_FAILED,
                    "slither exit 0 with empty JSON is a parse failure, not a clean report",
                )
            raise ToolError(PARSER_FAILED, "slither produced no JSON output")
        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError as error:
            raise ToolError(PARSER_FAILED, f"slither JSON parse failed: {error}") from error
        if not isinstance(payload, dict):
            raise ToolError(PARSER_FAILED, "slither JSON root must be an object")
        alerts: list[SlitherAlert] = []
        facts: list[SlitherCompilationFact] = []
        error_field = payload.get("error")
        compile_error = bool(error_field) or raw.failure_type == "compile"
        if error_field:
            facts.append(SlitherCompilationFact(kind="compiler_error", detail=str(error_field)[:2048]))
        results = payload.get("results") if isinstance(payload.get("results"), dict) else {}
        detectors = results.get("detectors") if isinstance(results, dict) else []
        if isinstance(detectors, list):
            for item in detectors:
                if not isinstance(item, dict):
                    continue
                check = str(item.get("check") or "unknown")
                description = str(item.get("description") or "")
                spans: list[SlitherSpan] = []
                elements = item.get("elements")
                if isinstance(elements, list):
                    for element in elements:
                        if isinstance(element, dict):
                            spans.extend(_spans_from_element(element))
                alerts.append(
                    SlitherAlert(
                        check=check,
                        severity=str(item.get("impact") or item.get("severity") or "unknown"),
                        confidence=str(item.get("confidence") or "unknown"),
                        description=description[:2048],
                        spans=spans,
                        classification=classify_alert(check, description),  # type: ignore[arg-type]
                    )
                )
        printers = results.get("printers") if isinstance(results, dict) else []
        if isinstance(printers, list) and printers:
            facts.append(SlitherCompilationFact(kind="printers", detail=f"{len(printers)} printer results"))
        facts.append(
            SlitherCompilationFact(
                kind="success_flag",
                detail=str(payload.get("success")),
            )
        )
        version = parse_slither_version(raw.stderr.decode("utf-8", errors="replace")) or "0.11.5"
        return SlitherRunResult(
            slither_version=version,
            alerts=alerts,
            compilation_facts=facts,
            compile_error=compile_error,
        )
