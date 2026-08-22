"""Foundry (forge) adapter: detect forge/cast/anvil, copy-on-write test, parse JSON."""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ayran.graph.canonical import canonical_hash
from ayran.tools.base import (
    ExecutableAdapter,
    _env_overlay,
    build_argv,
    filter_env,
    invoke_executable,
    mapping_of,
    resolve_executable,
    unique_hashes,
)
from ayran.tools.errors import PARSER_FAILED, UNAVAILABLE, ToolError
from ayran.tools.types import (
    ALIAS_FOUNDRY,
    DetectionResult,
    Environment,
    ExecutionPolicy,
    FoundryBuildDiscovery,
    FoundryRunRequest,
    FoundryRunResult,
    FoundryTestCase,
    RawRun,
)

_VERSION_RE = re.compile(r"(?:forge(?:\s+Version:)?)\s*(?:Version:\s*)?([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)
_IGNORE_DIRS = {"out", "cache", "broadcast", ".git", "node_modules"}


def _extract_json_object(text: str) -> dict[str, Any] | None:
    start = text.find("{")
    if start < 0:
        return None
    try:
        payload, _end = json.JSONDecoder().raw_decode(text[start:])
    except json.JSONDecodeError as error:
        raise ToolError(PARSER_FAILED, f"forge JSON parse failed: {error}") from error
    if not isinstance(payload, dict):
        raise ToolError(PARSER_FAILED, "unexpected forge JSON array")
    return payload


def parse_foundry_version(text: str) -> str | None:
    match = _VERSION_RE.search(text) or re.search(r"(\d+\.\d+\.\d+)", text)
    return match.group(1) if match else None


def discover_build(project_root: Path) -> FoundryBuildDiscovery:
    remappings: list[str] = []
    remappings_txt = project_root / "remappings.txt"
    if remappings_txt.is_file():
        remappings.extend(
            line.strip() for line in remappings_txt.read_text(encoding="utf-8").splitlines() if line.strip()
        )
    foundry_toml = project_root / "foundry.toml"
    toml_text = foundry_toml.read_text(encoding="utf-8") if foundry_toml.is_file() else ""
    if toml_text:
        for line in toml_text.splitlines():
            stripped = line.strip()
            if "remappings" in stripped and "=" in stripped:
                remappings.append(stripped)
    payload = {
        "foundry_toml": toml_text,
        "remappings": remappings,
        "lib": (project_root / "lib").is_dir(),
    }
    return FoundryBuildDiscovery(
        foundry_toml=foundry_toml.is_file(),
        remappings_txt=remappings_txt.is_file(),
        lib_dir=(project_root / "lib").is_dir(),
        config_hash=canonical_hash(payload),
        remappings=remappings,
    )


def copy_project(project_root: Path) -> Path:
    destination = Path(tempfile.mkdtemp(prefix="ayran-tool-copy-foundry-"))

    def _ignore(directory: str, names: list[str]) -> set[str]:
        _ = directory
        return {name for name in names if name in _IGNORE_DIRS}

    shutil.copytree(project_root, destination, dirs_exist_ok=True, ignore=_ignore)
    return destination


def parse_forge_json(payload: dict[str, Any]) -> list[FoundryTestCase]:
    tests: list[FoundryTestCase] = []
    by_contract = _contract_results(payload)
    for contract, cases in by_contract.items():
        if not isinstance(cases, dict):
            continue
        for name, body in cases.items():
            if not isinstance(body, dict):
                continue
            if "status" not in body and "result" not in body:
                continue
            status_raw = str(body.get("status") or body.get("result") or "")
            lowered = status_raw.lower()
            if lowered in {"success", "pass", "passed"}:
                status: Any = "pass"
            elif lowered in {"skip", "skipped"}:
                status = "skip"
            else:
                status = "fail"
            tests.append(
                FoundryTestCase(
                    name=str(name),
                    contract=str(contract),
                    status=status,
                    gas=_gas_used(body),
                    reason=str(body["reason"]) if body.get("reason") else None,
                    traces_present=bool(body.get("traces")),
                )
            )
    return tests


def _contract_results(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize Foundry JSON: 1.7 file:Contract wrappers and older test_results maps."""

    top = payload.get("test_results") or payload.get("results")
    if isinstance(top, dict) and _looks_like_test_map(top):
        return {"unknown": top}
    if isinstance(top, dict) and any(_looks_like_test_map(value) for value in top.values() if isinstance(value, dict)):
        return top
    nested: dict[str, Any] = {}
    for key, value in payload.items():
        if not isinstance(value, dict):
            continue
        inner = value.get("test_results")
        if isinstance(inner, dict):
            nested[str(key)] = inner
        elif _looks_like_test_map(value):
            nested[str(key)] = value
    return nested


def _looks_like_test_map(value: dict[str, Any]) -> bool:
    return any(isinstance(item, dict) and ("status" in item or "result" in item) for item in value.values())


def _gas_used(body: dict[str, Any]) -> int | None:
    gas = body.get("gas")
    if isinstance(gas, int):
        return gas
    if isinstance(gas, dict):
        for key in ("total", "used", "gas"):
            inner = gas.get(key)
            if isinstance(inner, int):
                return inner
    kind = body.get("kind")
    if isinstance(kind, dict):
        for inner in kind.values():
            if isinstance(inner, int):
                return inner
            if isinstance(inner, dict):
                maybe = inner.get("gas") or inner.get("total")
                if isinstance(maybe, int):
                    return maybe
    return None


# forge coverage --report summary: path then first percent. The specified
# collector is the tight `path |? percent` form; a looser variant accepts
# extra table columns and box-drawing pipes used by live forge output.
_COVERAGE_SOL_RE = re.compile(
    r"([^\s|]+\.(?:sol))\s*\|?\s*([0-9]+(?:\.[0-9]+)?)%",
    re.IGNORECASE,
)
_COVERAGE_SOL_LOOSE_RE = re.compile(
    r"([^\s|│]+\.(?:sol))\b.*?([0-9]+(?:\.[0-9]+)?)%",
    re.IGNORECASE,
)
_COVERAGE_TOTAL_RE = re.compile(
    r"\bTotal\b.*?([0-9]+(?:\.[0-9]+)?)%",
    re.IGNORECASE,
)


def _coverage_path_key(path: str) -> str:
    return path.replace("\\", "/").strip().lstrip("./")


def _coverage_percent_fraction(raw: str) -> float:
    return float(raw) / 100.0


def _coverage_sol_rows(text: str) -> list[tuple[str, float]]:
    rows: list[tuple[str, float]] = []
    for line in text.splitlines():
        match = _COVERAGE_SOL_RE.search(line) or _COVERAGE_SOL_LOOSE_RE.search(line)
        if match is None:
            continue
        rows.append((_coverage_path_key(match.group(1)), _coverage_percent_fraction(match.group(2))))
    return rows


def _coverage_total_fraction(text: str) -> float | None:
    for line in text.splitlines():
        if re.search(r"\.(?:sol)\b", line, re.IGNORECASE):
            continue
        match = _COVERAGE_TOTAL_RE.search(line)
        if match is not None:
            return _coverage_percent_fraction(match.group(1))
    return None


def _coverage_path_matches(row_path: str, patched_files: Sequence[str]) -> bool:
    row = _coverage_path_key(row_path)
    for item in patched_files:
        target = _coverage_path_key(item)
        if not target:
            continue
        if row == target or row.endswith("/" + target) or target.endswith("/" + row):
            return True
    return False


def parse_forge_coverage_summary(
    text: str,
    patched_files: Sequence[str] | None = None,
) -> float | None:
    """Parse ``forge coverage --report summary`` into a 0..1 fraction.

    Selection: (1) rows whose relative path equals a patched source file;
    (2) the sole ``.sol`` row; (3) a Total row; else None.
    """

    if not isinstance(text, str) or not text.strip():
        return None
    try:
        rows = _coverage_sol_rows(text)
        wanted = [item for item in (patched_files or ()) if str(item).strip()]
        if wanted:
            matched = [percent for path, percent in rows if _coverage_path_matches(path, wanted)]
            if matched:
                return min(matched)
        if len(rows) == 1:
            return rows[0][1]
        total = _coverage_total_fraction(text)
        if total is not None:
            return total
    except (TypeError, ValueError):
        return None
    return None


def run_forge_coverage_summary(
    *,
    project_root: Path,
    match_test: str,
    patched_files: Sequence[str] = (),
    timeout_seconds: int = 900,
    environment: Environment | None = None,
) -> dict[str, Any]:
    """Supervised ``forge coverage --report summary`` in an existing sandbox.

    Argv-only via ``resolve_executable`` + ``invoke_executable``. On any
    failure returns an empty summary so callers treat coverage as None
    (INV-5.7 fail-closed).
    """

    empty: dict[str, Any] = {
        "tool_run": {"exit_code": None, "limits": {}},
        "parsed": None,
        "coverage_summary": "",
        "failure_type": "prerequisite",
    }
    try:
        root = Path(project_root)
        if not root.is_dir():
            return empty
        if environment is None:
            from ayran.tools.doctor import default_environment

            environment = default_environment()
        argv = [
            "forge",
            "coverage",
            "--report",
            "summary",
            "--no-match-test",
            str(match_test),
        ]
        resolved = resolve_executable(argv[0], env=environment, path_env=environment.path)
        argv[0] = str(resolved)
        overlay = _env_overlay(environment)
        filtered = filter_env(
            None,
            extra_allowlist=("FOUNDRY_PROFILE", "FOUNDRY_ETH_RPC_URL", "ETH_RPC_URL"),
            overlay=overlay,
        )
        raw = invoke_executable(
            argv,
            cwd=root,
            env=filtered,
            timeout_seconds=timeout_seconds,
            max_output_bytes=50 * 1024 * 1024,
            graceful_stop_seconds=2,
            input_paths=[path for path in root.rglob("*") if path.is_file()][:256],
        )
        text = raw.stdout.decode("utf-8", errors="replace")
        if not text.strip():
            text = raw.stderr.decode("utf-8", errors="replace")
        coverage = parse_forge_coverage_summary(text, patched_files)
        return {
            "tool_run": {
                "exit_code": raw.exit_code,
                "started_at": raw.started_at,
                "ended_at": raw.ended_at,
                "argv": list(raw.argv),
                "limits": {},
            },
            "parsed": None,
            "coverage_summary": text,
            "coverage": coverage,
            "failure_type": raw.failure_type,
        }
    except Exception:
        return empty


class FoundryAdapter(ExecutableAdapter):
    alias = ALIAS_FOUNDRY
    request_type = FoundryRunRequest
    extra_env_allowlist = ("FOUNDRY_PROFILE", "FOUNDRY_ETH_RPC_URL", "ETH_RPC_URL")

    def parse_version(self, output: str) -> str | None:
        return parse_foundry_version(output)

    def expected_upstream_version(self) -> str:
        return "1.7.1"

    async def detect(self, env: Environment) -> DetectionResult:
        detected = await super().detect(env)
        if detected.status != "available":
            return detected
        path_env = env.path
        missing: list[str] = []
        for binary in ("cast", "anvil"):
            try:
                resolve_executable(binary, env=env, path_env=path_env)
            except ToolError:
                missing.append(binary)
        if missing:
            detected.status = "unavailable_broken"
            detected.detail = f"forge present but missing companions: {', '.join(missing)}"
        return detected

    async def run(self, request: FoundryRunRequest, policy: ExecutionPolicy) -> RawRun:  # type: ignore[override]
        root = Path(request.project_root)
        if not root.is_dir():
            raise ToolError(UNAVAILABLE, f"Foundry project root {root} does not exist")
        working = copy_project(root)
        invocation = mapping_of(self.manifest.get("invocation"))
        template = invocation.get("argv_template")
        if not isinstance(template, list):
            raise ToolError("CONTRACT_INVALID", "foundry argv_template is missing")
        argv = build_argv([str(item) for item in template], {})
        if request.match_test:
            argv.extend(["--match-test", request.match_test])
        if request.match_path:
            argv.extend(["--match-path", request.match_path])
        if request.fork_block is not None:
            argv.extend(["--fork-block-number", str(request.fork_block)])
        if request.seed is not None:
            argv.extend(["--fuzz-seed", str(request.seed)])
        if request.json_output and "--json" not in argv:
            argv.append("--json")
        env = self.environment
        resolved = resolve_executable(argv[0], env=env, path_env=env.path)
        argv[0] = str(resolved)
        overlay = _env_overlay(env)
        # Fork URL, if present, is taken from the allowlisted env overlay and never copied into argv.
        filtered = filter_env(None, extra_allowlist=self.extra_env_allowlist, overlay=overlay)
        inputs = [path for path in working.rglob("*") if path.is_file()]
        raw = invoke_executable(
            argv,
            cwd=working,
            env=filtered,
            timeout_seconds=min(policy.timeout_seconds, self.timeout_seconds()),
            max_output_bytes=policy.max_output_bytes,
            graceful_stop_seconds=policy.graceful_stop_seconds,
            input_paths=inputs[:256],
        )
        raw.working_copy = str(working)
        raw.input_hashes = unique_hashes(raw.input_hashes)
        discovery = discover_build(working)
        raw.extra["build"] = discovery.model_dump()
        raw.extra["seed"] = request.seed
        if request.fork_url_ref or request.fork_block is not None:
            raw.extra["fork_identity_hash"] = canonical_hash(
                {
                    "fork_url_ref": request.fork_url_ref,
                    "fork_block": request.fork_block,
                }
            )
        stderr = raw.stderr.decode("utf-8", errors="replace")
        if raw.timeout:
            raw.failure_type = "timeout"
        elif "Error: " in stderr and "Compiler" in stderr:
            raw.failure_type = "compile"
        elif raw.exit_code not in {0, None}:
            raw.failure_type = "test"
        return raw

    def parse(self, raw: RawRun) -> FoundryRunResult:
        text = raw.stdout.decode("utf-8", errors="replace").strip()
        stderr = raw.stderr.decode("utf-8", errors="replace")
        compile_error = raw.failure_type == "compile" or (
            "Compiler run failed" in stderr or "Compilation failed" in stderr
        )
        tests: list[FoundryTestCase] = []
        payload = _extract_json_object(text)
        if payload is not None:
            tests = parse_forge_json(payload)
        elif raw.exit_code == 0 and not text:
            raise ToolError(
                PARSER_FAILED,
                "forge exit 0 with empty output is a parse failure, not a passing test suite",
            )
        elif not compile_error and text:
            raise ToolError(PARSER_FAILED, "forge output was not JSON")
        build = None
        if isinstance(raw.extra.get("build"), dict):
            build = FoundryBuildDiscovery.model_validate(raw.extra["build"])
        passed = sum(1 for item in tests if item.status == "pass")
        failed = sum(1 for item in tests if item.status == "fail")
        skipped = sum(1 for item in tests if item.status == "skip")
        version = parse_foundry_version(stderr) or "1.7.1"
        return FoundryRunResult(
            forge_version=version,
            solc_version=None,
            compile_error=compile_error,
            tests=tests,
            passed=passed,
            failed=failed,
            skipped=skipped,
            build=build,
            fork_identity_hash=str(raw.extra["fork_identity_hash"]) if raw.extra.get("fork_identity_hash") else None,
            seed=raw.extra.get("seed") if isinstance(raw.extra.get("seed"), int) else None,
        )
