"""Pashov Fizz-derived harness generator. Feature-flagged and not bundled."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ayran.graph.canonical import canonical_hash, utc_now
from ayran.tools.adapters.experimental import ExperimentalAdapter
from ayran.tools.base import (
    _env_overlay,
    build_argv,
    filter_env,
    invoke_executable,
    mapping_of,
    resolve_executable,
)
from ayran.tools.errors import PARSER_FAILED, POLICY_DENIED, UNAVAILABLE, ToolError
from ayran.tools.types import ExecutionPolicy, RawRun

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)")


class FizzHarnessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_dir: str
    output_dir: str
    properties_file: str = ""
    enable_experimental: bool = False
    replay: bool = True


class FizzActor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    permissions: list[str] = Field(default_factory=list)
    balances: dict[str, str] = Field(default_factory=dict)
    actions: list[str] = Field(default_factory=list)


class FizzHarnessManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    generator_version: str = "unknown"
    actors: list[FizzActor] = Field(default_factory=list)
    properties: list[str] = Field(default_factory=list)
    handlers: list[str] = Field(default_factory=list)
    engine: str = "echidna"
    target_hash: str = ""
    source_diff_hash: str = ""
    replay_status: str = "not_run"
    quarantined: bool = False


class FizzHarnessResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    experimental: bool = True
    generator_version: str = "unknown"
    harness: FizzHarnessManifest = Field(default_factory=FizzHarnessManifest)
    artifacts: list[str] = Field(default_factory=list)
    replay_passed: bool | None = None
    evidence_ceiling: str = "observed"


def parse_fizz_version(text: str) -> str | None:
    match = _VERSION_RE.search(text)
    return match.group(1) if match else None


def parse_harness_payload(payload: dict[str, Any], *, generator_version: str) -> FizzHarnessManifest:
    actors = []
    for item in payload.get("actors") or []:
        if not isinstance(item, dict):
            continue
        actors.append(
            FizzActor(
                name=str(item.get("name") or "actor"),
                permissions=[str(value) for value in (item.get("permissions") or [])],
                balances={str(key): str(value) for key, value in dict(item.get("balances") or {}).items()},
                actions=[str(value) for value in (item.get("actions") or item.get("action_domain") or [])],
            )
        )
    properties = [str(item) for item in (payload.get("properties") or []) if item]
    handlers = [str(item) for item in (payload.get("handlers") or []) if item]
    return FizzHarnessManifest(
        generator_version=generator_version,
        actors=actors,
        properties=properties,
        handlers=handlers,
        engine=str(payload.get("engine") or "echidna"),
        target_hash=str(payload.get("target_hash") or ""),
        source_diff_hash=str(payload.get("source_diff_hash") or payload.get("source_diff") or ""),
        replay_status=str(payload.get("replay_status") or "not_run"),
        quarantined=bool(payload.get("quarantined")),
    )


class FizzAdapter(ExperimentalAdapter):
    alias = "fizz.harness"
    request_type = FizzHarnessRequest

    def parse_version(self, output: str) -> str | None:
        return parse_fizz_version(output)

    def expected_upstream_version(self) -> str:
        provenance = self.manifest.get("provenance")
        first: Any = provenance[0] if isinstance(provenance, list) and provenance else {}
        upstream = mapping_of(first)
        return str(upstream.get("source_version") or "1.0.0")

    async def run(self, request: BaseModel, policy: ExecutionPolicy) -> RawRun:
        if not isinstance(request, FizzHarnessRequest):
            raise ToolError("CONTRACT_INVALID", "FizzHarnessRequest required")
        if not self.is_enabled(policy) and not request.enable_experimental:
            raise ToolError(
                POLICY_DENIED,
                "fizz.harness is feature-flagged and disabled by default",
                details={"alias": self.alias, "experimental": True},
            )
        sandboxed = self.sandboxed_policy(policy)
        env = self.environment
        invocation = mapping_of(self.manifest.get("invocation"))
        template = invocation.get("argv_template") or ["fizz", "generate", "--target", "{target_dir}"]
        path_env = env.path
        try:
            resolved = resolve_executable("fizz", env=env, path_env=path_env)
        except ToolError as error:
            raise ToolError(UNAVAILABLE, "Fizz is not installed; capability degrades explicitly") from error
        substitutions = {
            "target_dir": request.target_dir,
            "output_dir": request.output_dir,
            "properties_file": request.properties_file or "properties.json",
        }
        argv = build_argv([str(resolved), *[str(item) for item in list(template)[1:]]], substitutions)
        filtered = filter_env(None, extra_allowlist=self.extra_env_allowlist, overlay=_env_overlay(env))
        filtered["AYRAN_EXPERIMENTAL"] = "true"
        target = Path(request.target_dir)
        output = Path(request.output_dir)
        output.mkdir(parents=True, exist_ok=True)
        raw = invoke_executable(
            argv,
            cwd=target if target.is_dir() else None,
            env=filtered,
            timeout_seconds=sandboxed.timeout_seconds,
            input_paths=[target] if target.is_dir() else (),
            extra_output_files=tuple(sorted(output.glob("*"))) if output.is_dir() else (),
        )
        raw.extra["experimental"] = True
        raw.extra["tool_version"] = self.parse_version(
            ((raw.stdout or b"") + b"\n" + (raw.stderr or b"")).decode("utf-8", errors="replace")
        ) or "unknown"
        if request.replay:
            replay = self._replay_foundry(target, output, filtered, sandboxed)
            raw.extra["replay_status"] = replay
            if replay == "failed":
                raw.extra["harness_quarantined"] = True
        raw.extra["started_note"] = utc_now()
        return raw

    def _replay_foundry(
        self,
        target: Path,
        output: Path,
        env: dict[str, str],
        policy: ExecutionPolicy,
    ) -> str:
        try:
            forge = resolve_executable("forge", env=self.environment, path_env=self.environment.path)
        except ToolError:
            return "skipped"
        harness = next(iter(sorted(output.glob("*.t.sol"))), None)
        if harness is None and not (target / "test").is_dir():
            return "skipped"
        raw = invoke_executable(
            [str(forge), "test", "--json"],
            cwd=target if target.is_dir() else None,
            env=env,
            timeout_seconds=min(120, policy.timeout_seconds),
        )
        if raw.timeout or (raw.exit_code not in {0, None} and raw.exit_code != 0):
            return "failed"
        return "passed"

    def parse(self, raw: RawRun) -> FizzHarnessResult:
        text = ((raw.stdout or b"") + b"\n" + (raw.stderr or b"")).decode("utf-8", errors="replace")
        payload: dict[str, Any] | None = None
        start = text.find("{")
        if start >= 0:
            try:
                loaded, _end = json.JSONDecoder().raw_decode(text[start:])
                if isinstance(loaded, dict):
                    payload = loaded
            except json.JSONDecodeError as error:
                raise ToolError(PARSER_FAILED, f"fizz JSON parse failed: {error}") from error
        if payload is None:
            payload = {
                "actors": [],
                "properties": [],
                "handlers": [],
                "target_hash": canonical_hash({"stdout": raw.stdout_hash}),
            }
        version = str(raw.extra.get("tool_version") or parse_fizz_version(text) or "unknown")
        harness = parse_harness_payload(payload, generator_version=version)
        replay = str(raw.extra.get("replay_status") or "not_run")
        harness.replay_status = replay
        harness.quarantined = replay == "failed" or bool(raw.extra.get("harness_quarantined"))
        return FizzHarnessResult(
            generator_version=version,
            harness=harness,
            artifacts=sorted(raw.output_file_hashes.keys()),
            replay_passed=None if replay in {"not_run", "skipped"} else replay == "passed",
        )
