"""solc executable adapter: detect, compile, parse, pragma version resolution."""

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
    bytes_hash,
    file_sha256,
    filter_env,
    invoke_executable,
    mapping_of,
    resolve_executable,
    unique_hashes,
)
from ayran.tools.errors import PARSER_FAILED, ToolError
from ayran.tools.types import (
    ALIAS_SOLC,
    ExecutionPolicy,
    RawRun,
    SolcCompileRequest,
    SolcCompileResult,
    SolcContractSummary,
)

_VERSION_RE = re.compile(r"Version:\s*([0-9]+\.[0-9]+\.[0-9]+(?:\+[0-9A-Za-z.]+)?)")
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_SEMVER_RE = re.compile(r"([0-9]+)\.([0-9]+)\.([0-9]+)")


def parse_solc_version(text: str) -> str | None:
    match = _VERSION_RE.search(text) or re.search(r"(\d+\.\d+\.\d+)", text)
    return match.group(1) if match else None


def _tuple_version(value: str) -> tuple[int, int, int]:
    match = _SEMVER_RE.search(value)
    if match is None:
        return (0, 0, 0)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def pragma_matches(constraint: str, version: str) -> bool:
    observed = _tuple_version(version)
    text = constraint.strip()
    if text.startswith("^"):
        base = _tuple_version(text[1:])
        return observed >= base and observed[0] == base[0] and (observed[0] > 0 or observed[1] == base[1])
    if text.startswith(">="):
        return observed >= _tuple_version(text[2:])
    if text.startswith(">"):
        return observed > _tuple_version(text[1:])
    if text.startswith("=") or _SEMVER_RE.fullmatch(text.strip()):
        return observed == _tuple_version(text.lstrip("="))
    return observed == _tuple_version(text)


def resolve_pragma_version(source_paths: list[str], available: str) -> str:
    """Record the best available solc version against the first pragma constraint."""

    for path_text in source_paths:
        path = Path(path_text)
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = _PRAGMA_RE.search(text)
        if match is None:
            continue
        constraint = match.group(1).strip()
        if pragma_matches(constraint, available):
            return available
        return available
    return available


class SolcAdapter(ExecutableAdapter):
    alias = ALIAS_SOLC
    request_type = SolcCompileRequest

    def parse_version(self, output: str) -> str | None:
        return parse_solc_version(output)

    def expected_upstream_version(self) -> str:
        return "0.8.28"

    async def run(self, request: SolcCompileRequest, policy: ExecutionPolicy) -> RawRun:  # type: ignore[override]
        env = self.environment
        path_env = env.path
        invocation = mapping_of(self.manifest.get("invocation"))
        template = invocation.get("argv_template")
        if not isinstance(template, list):
            raise ToolError("CONTRACT_INVALID", "solc argv_template is missing")
        output_dir = Path(request.output_dir) if request.output_dir else Path(tempfile.mkdtemp(prefix="ayran-solc-out-"))
        output_dir.mkdir(parents=True, exist_ok=True)
        sources = [str(Path(item)) for item in request.source_paths]
        substitutions: dict[str, str | list[str]] = {
            "output_dir": str(output_dir),
            "source_paths": sources,
        }
        argv = build_argv([str(item) for item in template], substitutions)
        if request.combined_json:
            stripped: list[str] = []
            skip_next = False
            for item in argv:
                if skip_next:
                    skip_next = False
                    continue
                if item == "--output-dir":
                    skip_next = True
                    continue
                stripped.append(item)
            argv = stripped
            if "--combined-json" not in argv:
                argv = [argv[0], "--combined-json", "abi,bin,hashes", *argv[1:]]
        if not request.optimize:
            argv = [item for item in argv if item != "--optimize"]
        resolved = resolve_executable(argv[0], env=env, path_env=path_env)
        argv[0] = str(resolved)
        filtered = filter_env(
            None,
            extra_allowlist=self.extra_env_allowlist,
            overlay=_env_overlay(env),
        )
        inputs = [Path(item) for item in sources]
        raw = invoke_executable(
            argv,
            cwd=None,
            env=filtered,
            timeout_seconds=min(policy.timeout_seconds, self.timeout_seconds()),
            max_output_bytes=policy.max_output_bytes,
            graceful_stop_seconds=policy.graceful_stop_seconds,
            input_paths=inputs,
            extra_output_files=list(output_dir.rglob("*")) if output_dir.exists() else [],
        )
        extra_files = {
            str(path): file_sha256(path) for path in output_dir.rglob("*") if path.is_file()
        }
        raw.output_file_hashes.update(extra_files)
        raw.input_hashes = unique_hashes([*raw.input_hashes, *[file_sha256(path) for path in inputs if path.is_file()]])
        tool_version_raw = raw.extra.get("tool_version")
        available = tool_version_raw if isinstance(tool_version_raw, str) else "0.8.28"
        detected_version = parse_solc_version((raw.stderr + raw.stdout).decode("utf-8", errors="replace")) or available
        raw.extra["resolved_version"] = resolve_pragma_version(sources, detected_version)
        raw.extra["output_dir"] = str(output_dir)
        if raw.timeout:
            raw.failure_type = "timeout"
        elif raw.exit_code not in {0, None} and b"Error" in raw.stderr:
            raw.failure_type = "compile"
        return raw

    def parse(self, raw: RawRun) -> SolcCompileResult:
        text = raw.stdout.decode("utf-8", errors="replace").strip()
        stderr = raw.stderr.decode("utf-8", errors="replace")
        version = parse_solc_version(stderr) or parse_solc_version(text) or str(raw.extra.get("resolved_version") or "unknown")
        warnings = [line.strip() for line in stderr.splitlines() if "Warning" in line]
        errors = [line.strip() for line in stderr.splitlines() if "Error" in line]
        contracts: list[SolcContractSummary] = []
        if not text and not raw.output_file_hashes and not errors:
            raise ToolError(
                PARSER_FAILED,
                "solc produced empty output; exit code does not validate a compile result",
            )
        payload: Any = None
        if not text.startswith("{") and isinstance(raw.extra.get("output_dir"), str):
            combined = Path(str(raw.extra["output_dir"])) / "combined.json"
            if combined.is_file():
                text = combined.read_text(encoding="utf-8", errors="replace").strip()
        if text.startswith("{"):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as error:
                raise ToolError(PARSER_FAILED, f"solc JSON parse failed: {error}") from error
        if isinstance(payload, dict):
            contracts_obj = payload.get("contracts")
            if isinstance(contracts_obj, dict):
                for name, body in contracts_obj.items():
                    bytecode = ""
                    abi_raw = ""
                    if isinstance(body, dict):
                        bytecode = str(body.get("bin") or body.get("bytecode") or "")
                        abi_raw = json.dumps(body.get("abi") or "")
                    elif isinstance(body, str):
                        bytecode = body
                    contracts.append(
                        SolcContractSummary(
                            name=str(name),
                            bytecode_size=len(bytecode) // 2 if bytecode else 0,
                            abi_hash=bytes_hash(abi_raw.encode("utf-8")) if abi_raw else None,
                        )
                    )
        if raw.exit_code not in {0, None} and not errors:
            errors.append(f"solc exited {raw.exit_code}")
        if raw.exit_code == 0 and not contracts and not errors and not text:
            raise ToolError(PARSER_FAILED, "solc exit 0 with empty/malformed output is a parse failure")
        return SolcCompileResult(
            compiler_version=version,
            contracts=contracts,
            warnings=warnings,
            errors=errors,
            resolved_version=str(raw.extra.get("resolved_version") or version),
        )
