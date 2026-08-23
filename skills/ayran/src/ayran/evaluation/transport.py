"""Arm transport seam. CI uses a scripted replay; live Prime stays unconfigured.

LivePrimeTransport CLI assumptions (unverified against a stock Prime binary in
this milestone — owner must confirm before any paid run):

- executable: ``prime`` on PATH, or ``AYRAN_PRIME_BIN``
- flags: ``--ayran --print`` (attach the Ayran package; print/headless mode)
- cwd: the target workspace
- no API keys are injected by Ayran
- token usage: JSON lines on stdout with ``input_tokens`` / ``output_tokens``;
  if absent, usage is None and cost uses token-unit disclosure

If a flag differs from the installed Prime, that is a deviation to resolve
before the owner operates a live arm. ``run`` refuses unless ``configured=True``.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from ayran.evaluation.errors import LIVE_TRANSPORT_UNCONFIGURED, EvaluationError
from ayran.evaluation.models import ArmId
from ayran.evaluation.targets import TargetManifest
from ayran.graph.canonical import utc_now


class ArmSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    arm: ArmId
    capabilities: list[str] = Field(default_factory=list)


class ArmUsage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    input_tokens: int | None = None
    output_tokens: int | None = None


class ArmTranscript(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[dict[str, Any]] = Field(default_factory=list)
    usage: ArmUsage = Field(default_factory=ArmUsage)
    started_at: str = ""
    ended_at: str = ""
    exit_status: str = "ok"
    stdout: str = ""
    stderr: str = ""


@runtime_checkable
class ArmTransport(Protocol):
    def run(self, arm: ArmSpec, target: TargetManifest, budget: Mapping[str, Any]) -> ArmTranscript:
        """Execute one arm against one target under ``budget``."""


class ScriptedArmTransport:
    """CI transport: replay canned transcripts, including timeout/empty/crash."""

    def __init__(self, scripts: Mapping[str, ArmTranscript] | None = None) -> None:
        self.scripts = dict(scripts or {})
        self.calls: list[tuple[ArmId, str]] = []
        self.invocations = 0

    def run(self, arm: ArmSpec, target: TargetManifest, budget: Mapping[str, Any]) -> ArmTranscript:
        _ = budget
        self.invocations += 1
        self.calls.append((arm.arm, target.target_id))
        key = f"{arm.arm}:{target.target_id}"
        if key in self.scripts:
            return self.scripts[key]
        if arm.arm in self.scripts:
            return self.scripts[arm.arm]
        stamp = utc_now()
        return ArmTranscript(started_at=stamp, ended_at=stamp, exit_status="empty")


class LivePrimeTransport:
    """UNCONFIGURED live transport. Does not spawn a process unless explicitly enabled."""

    def __init__(
        self,
        *,
        configured: bool = False,
        prime_bin: str | None = None,
        extra_args: Sequence[str] | None = None,
        timeout_s: float = 3600.0,
    ) -> None:
        self.configured = configured
        self.prime_bin = prime_bin or os.environ.get("AYRAN_PRIME_BIN", "prime")
        self.extra_args = list(extra_args or ("--ayran", "--print"))
        self.timeout_s = timeout_s

    def run(self, arm: ArmSpec, target: TargetManifest, budget: Mapping[str, Any]) -> ArmTranscript:
        _ = arm
        if not self.configured:
            raise EvaluationError(
                LIVE_TRANSPORT_UNCONFIGURED,
                "LivePrimeTransport ships unconfigured; owner must enable it after verifying CLI flags",
            )
        timeout = float(budget.get("timeout_s") or self.timeout_s)
        started = utc_now()
        argv = [self.prime_bin, *self.extra_args]
        completed = subprocess.run(
            argv,
            cwd=str(target.workspace()),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        ended = utc_now()
        usage = _parse_usage(completed.stdout)
        status = "ok" if completed.returncode == 0 else "crash"
        return ArmTranscript(
            events=[],
            usage=usage,
            started_at=started,
            ended_at=ended,
            exit_status=status,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


def _parse_usage(stdout: str) -> ArmUsage:
    for line in stdout.splitlines():
        text = line.strip()
        if not text.startswith("{"):
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        incoming = payload.get("input_tokens")
        outgoing = payload.get("output_tokens")
        if incoming is None and outgoing is None:
            continue
        return ArmUsage(
            input_tokens=int(incoming) if incoming is not None else None,
            output_tokens=int(outgoing) if outgoing is not None else None,
        )
    return ArmUsage()
