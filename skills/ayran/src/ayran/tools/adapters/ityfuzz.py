"""ItyFuzz experimental hybrid-sequence adapter. Detect-only unless explicitly enabled."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from ayran.tools.adapters.experimental import ExperimentalAdapter, ExperimentalRunResult
from ayran.tools.errors import POLICY_DENIED, ToolError
from ayran.tools.types import ExecutionPolicy, RawRun


class ItyfuzzRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_dir: str = ""
    enable_experimental: bool = False


class ItyfuzzRunResult(ExperimentalRunResult):
    pass


class ItyFuzzAdapter(ExperimentalAdapter):
    alias = "ityfuzz.hybrid"
    request_type = ItyfuzzRunRequest

    async def run(self, request: BaseModel, policy: ExecutionPolicy) -> RawRun:
        enabled = self.is_enabled(policy) or bool(getattr(request, "enable_experimental", False))
        if not enabled:
            raise ToolError(
                POLICY_DENIED,
                "ityfuzz.hybrid is experimental and disabled by default",
                details={"alias": self.alias, "experimental": True},
            )
        raise ToolError(
            POLICY_DENIED,
            "ityfuzz.hybrid has no production runner in M8",
            details={"alias": self.alias, "experimental": True},
        )
