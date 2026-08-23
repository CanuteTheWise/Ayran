"""Arm transport seam. CI uses a scripted replay; live Prime stays unconfigured.

LivePrimeTransport CLI assumptions (unverified against a stock Prime binary in
this milestone — owner must confirm before any paid run):

- executable: ``prime`` on PATH, or ``AYRAN_PRIME_BIN``
- cwd: the target workspace
- no API keys are injected by Ayran
- token usage: JSON lines on stdout with ``input_tokens`` / ``output_tokens``;
  if absent, usage is None and cost uses token-unit disclosure

Invocation profiles are derived from ``ArmSpec.capabilities``, never from a
hardcoded flag list:

- **stock** (no Ayran capabilities — only ``prime.stock`` or empty):
  ``argv = [prime_bin, "--print", task_text]``. Process env is unchanged
  (no ``AYRAN_*`` variables injected).
- **ayran** (any capability other than ``prime.stock``):
  ``argv = [prime_bin, "--ayran", "--print", task_text]``. When the
  transport is given ``ayran_socket_path`` / ``ayran_token_file``, those
  values are forwarded as ``AYRAN_SOCKET_PATH`` / ``AYRAN_TOKEN_FILE``.
  The harness may pre-start the sidecar out-of-band; this transport only
  forwards the boundary paths, it does not spawn the sidecar.

Headless context-pack injection currently arms via the ``--ayran`` flag.
Pack **injection** semantics in print mode are UNVERIFIED and will be
confirmed during live operation. The capability contract for this exam is
"Ayran verbs + sidecar boundary available", not "injection".

``extra_args`` remains an explicit override of the profile flags (task text
is still appended). If a flag differs from the installed Prime, that is a
deviation to resolve before the owner operates a live arm. ``run`` refuses
unless ``configured=True``.
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
from ayran.evaluation.targets import DEFAULT_TASK_TEXT, TargetManifest
from ayran.graph.canonical import utc_now

_STOCK_CAPABILITIES = frozenset({"prime.stock"})
_STOCK_FLAGS = ("--print",)
_AYRAN_FLAGS = ("--ayran", "--print")


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
    task_text: str = ""


@runtime_checkable
class ArmTransport(Protocol):
    def run(
        self,
        arm: ArmSpec,
        target: TargetManifest,
        budget: Mapping[str, Any],
        *,
        task_text: str = "",
    ) -> ArmTranscript:
        """Execute one arm against one target under ``budget``."""


class ScriptedArmTransport:
    """CI transport: replay canned transcripts, including timeout/empty/crash."""

    def __init__(self, scripts: Mapping[str, ArmTranscript] | None = None) -> None:
        self.scripts = dict(scripts or {})
        self.calls: list[tuple[ArmId, str]] = []
        self.invocations = 0

    def run(
        self,
        arm: ArmSpec,
        target: TargetManifest,
        budget: Mapping[str, Any],
        *,
        task_text: str = "",
    ) -> ArmTranscript:
        _ = budget
        _ = task_text
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
    """UNCONFIGURED live transport. Does not spawn a process unless explicitly enabled.

    Profiles (stock vs ayran) come from ``arm.capabilities``. The sidecar, if
    used, is assumed to have been started out-of-band; this class only forwards
    ``AYRAN_SOCKET_PATH`` / ``AYRAN_TOKEN_FILE`` when those paths are configured.
    """

    def __init__(
        self,
        *,
        configured: bool = False,
        prime_bin: str | None = None,
        extra_args: Sequence[str] | None = None,
        timeout_s: float = 3600.0,
        ayran_socket_path: str | None = None,
        ayran_token_file: str | None = None,
    ) -> None:
        self.configured = configured
        self.prime_bin = prime_bin or os.environ.get("AYRAN_PRIME_BIN", "prime")
        self.extra_args = list(extra_args) if extra_args is not None else None
        self.timeout_s = timeout_s
        self.ayran_socket_path = ayran_socket_path
        self.ayran_token_file = ayran_token_file

    def run(
        self,
        arm: ArmSpec,
        target: TargetManifest,
        budget: Mapping[str, Any],
        *,
        task_text: str = "",
    ) -> ArmTranscript:
        if not self.configured:
            raise EvaluationError(
                LIVE_TRANSPORT_UNCONFIGURED,
                "LivePrimeTransport ships unconfigured; owner must enable it after verifying CLI flags",
            )
        resolved_task = task_text or target.task_text or DEFAULT_TASK_TEXT
        timeout = float(budget.get("timeout_s") or self.timeout_s)
        started = utc_now()
        argv, env = self._invocation(arm, resolved_task)
        try:
            completed = subprocess.run(
                argv,
                cwd=str(target.workspace()),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            ended = utc_now()
            stdout = _captured_text(exc.stdout if exc.stdout is not None else exc.output)
            stderr = _captured_text(exc.stderr)
            exit_status = "timeout"
            return ArmTranscript(
                events=[],
                usage=_parse_usage(stdout),
                started_at=started,
                ended_at=ended,
                exit_status=exit_status,
                stdout=stdout,
                stderr=stderr,
                task_text=resolved_task,
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
            task_text=resolved_task,
        )

    def _invocation(
        self, arm: ArmSpec, task_text: str
    ) -> tuple[list[str], dict[str, str] | None]:
        profile = _profile_from_capabilities(arm.capabilities)
        flags: Sequence[str]
        if self.extra_args is not None:
            flags = self.extra_args
        elif profile == "ayran":
            flags = _AYRAN_FLAGS
        else:
            flags = _STOCK_FLAGS
        argv = [self.prime_bin, *flags, task_text]
        return argv, self._env_for_profile(profile)

    def _env_for_profile(self, profile: str) -> dict[str, str] | None:
        if profile != "ayran":
            return None
        extras: dict[str, str] = {}
        if self.ayran_socket_path:
            extras["AYRAN_SOCKET_PATH"] = self.ayran_socket_path
        if self.ayran_token_file:
            extras["AYRAN_TOKEN_FILE"] = self.ayran_token_file
        if not extras:
            return None
        env = os.environ.copy()
        env.update(extras)
        return env


def _profile_from_capabilities(capabilities: Sequence[str]) -> str:
    if any(item not in _STOCK_CAPABILITIES for item in capabilities):
        return "ayran"
    return "stock"


def _captured_text(blob: str | bytes | None) -> str:
    if blob is None:
        return ""
    if isinstance(blob, bytes):
        return blob.decode("utf-8", errors="replace")
    return blob


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
