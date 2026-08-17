"""Experimental executable adapters: feature-flagged, disabled by default."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ayran.tools.base import ExecutableAdapter, filter_env, mapping_of
from ayran.tools.errors import POLICY_DENIED, ToolError
from ayran.tools.types import Environment, ExecutionPolicy, RawRun

EXPERIMENTAL_ENV_ALLOWLIST: tuple[str, ...] = ()


class ExperimentalRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_dir: str = ""
    output_dir: str = ""
    properties_file: str = ""
    enable_experimental: bool = False


class ExperimentalRunResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    experimental: bool = True
    status: str = "disabled"
    detail: str = "experimental adapter is disabled by default"
    harness: dict[str, Any] = Field(default_factory=dict)


class ExperimentalAdapter(ExecutableAdapter):
    """Disabled-by-default adapter with stricter sandboxing than production tools."""

    alias: str = ""
    experimental: bool = True
    enabled: bool = False
    extra_env_allowlist: tuple[str, ...] = EXPERIMENTAL_ENV_ALLOWLIST
    request_type: type[BaseModel] = ExperimentalRunRequest

    def version_compatible(self, observed: str, expected: str) -> bool:
        _ = expected
        return bool(observed)

    def timeout_seconds(self) -> int:
        return max(int(self.manifest.get("timeout_seconds") or 1800), 1800)

    def is_enabled(self, policy: ExecutionPolicy | None = None) -> bool:
        return bool(
            getattr(self, "enabled", False)
            or (policy is not None and getattr(policy, "allow_experimental", False))
        )

    def sandboxed_policy(self, policy: ExecutionPolicy) -> ExecutionPolicy:
        resources = mapping_of(self.manifest.get("resources"))
        memory_cap = min(int(resources.get("memory_mib") or policy.memory_mib), 2048)
        cpu_cap = min(int(resources.get("cpu") or policy.cpu), 2)
        return ExecutionPolicy(
            allowed_paths=policy.allowed_paths,
            network="none",
            allowed_hosts=(),
            cpu=max(1, cpu_cap),
            memory_mib=max(64, memory_cap),
            disk_mib=min(policy.disk_mib, int(resources.get("disk_mib") or policy.disk_mib)),
            timeout_seconds=max(policy.timeout_seconds, self.timeout_seconds()),
            max_output_bytes=policy.max_output_bytes,
            allow_install=False,
            offline=True,
            scope_hash=policy.scope_hash,
            graceful_stop_seconds=policy.graceful_stop_seconds,
            allow_experimental=self.is_enabled(policy),
        )

    def filtered_env(self, env: Environment) -> dict[str, str]:
        overlay: dict[str, str] = {}
        if env.path:
            overlay["PATH"] = env.path
        if env.home:
            overlay["HOME"] = str(env.home)
        if env.tmpdir:
            overlay["TMPDIR"] = str(env.tmpdir)
        return filter_env(None, extra_allowlist=self.extra_env_allowlist, overlay=overlay)

    async def run(self, request: BaseModel, policy: ExecutionPolicy) -> RawRun:
        enabled = self.is_enabled(policy) or bool(getattr(request, "enable_experimental", False))
        if not enabled:
            raise ToolError(
                POLICY_DENIED,
                f"experimental adapter {self.alias} is disabled; enable it explicitly in config",
                details={"alias": self.alias, "experimental": True},
            )
        raise ToolError(
            POLICY_DENIED,
            f"experimental adapter {self.alias} has no production runner in M8",
            details={"alias": self.alias, "experimental": True},
        )

    def parse(self, raw: RawRun) -> BaseModel:
        _ = raw
        return ExperimentalRunResult(status="disabled", detail=f"{self.alias} experimental placeholder")
