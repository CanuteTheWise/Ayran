"""Load, validate, and probe capability manifests."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from ayran.api.validators import ContractValidationError, validate_contract
from ayran.tools.adapters.experimental import ExperimentalAdapter
from ayran.tools.adapters.fizz import FizzAdapter
from ayran.tools.adapters.foundry import FoundryAdapter
from ayran.tools.adapters.ityfuzz import ItyFuzzAdapter
from ayran.tools.adapters.slither import SlitherAdapter
from ayran.tools.adapters.solc import SolcAdapter
from ayran.tools.adapters.solodit import SoloditAdapter
from ayran.tools.base import HttpTransport, ToolAdapter
from ayran.tools.errors import UNAVAILABLE, ToolError
from ayran.tools.types import (
    ALIAS_FOUNDRY,
    ALIAS_SLITHER,
    ALIAS_SOLC,
    ALIAS_SOLODIT,
    DEFAULT_ALIASES,
    EXPERIMENTAL_ALIASES,
    ID_BY_ALIAS,
    CapabilityStatus,
    DetectionResult,
    Environment,
    HealthResult,
)
from ayran.tools.yaml_lite import YamlLiteError, load_yaml

KNOWN_ALIASES = DEFAULT_ALIASES | EXPERIMENTAL_ALIASES


def _build_adapter(
    alias: str,
    manifest: dict[str, Any],
    environment: Environment,
    http_transport: HttpTransport | None,
) -> ToolAdapter:
    if alias == ALIAS_SOLODIT:
        return cast(ToolAdapter, SoloditAdapter(manifest, environment=environment, transport=http_transport))
    if alias == ALIAS_SOLC:
        return cast(ToolAdapter, SolcAdapter(manifest, environment=environment))
    if alias == ALIAS_FOUNDRY:
        return cast(ToolAdapter, FoundryAdapter(manifest, environment=environment))
    if alias == ALIAS_SLITHER:
        return cast(ToolAdapter, SlitherAdapter(manifest, environment=environment))
    if alias == "fizz.harness":
        return cast(ToolAdapter, FizzAdapter(manifest, environment=environment))
    if alias == "ityfuzz.hybrid":
        return cast(ToolAdapter, ItyFuzzAdapter(manifest, environment=environment))
    if alias in EXPERIMENTAL_ALIASES:
        adapter = ExperimentalAdapter(manifest, environment=environment)
        adapter.alias = alias
        return cast(ToolAdapter, adapter)
    raise ToolError("CONTRACT_INVALID", f"no adapter registered for {alias}")


def default_capabilities_dir() -> Path:
    repo = Path(__file__).resolve().parents[5]
    candidate = repo / "capabilities"
    if candidate.is_dir():
        return candidate
    return Path(__file__).resolve().parent / "capabilities"


def load_manifest_file(path: Path) -> dict[str, Any]:
    try:
        loaded = load_yaml(path.read_text(encoding="utf-8"))
    except YamlLiteError as error:
        raise ToolError("CONTRACT_INVALID", f"capability manifest {path.name} is not valid YAML: {error}") from error
    if not isinstance(loaded, dict):
        raise ToolError("CONTRACT_INVALID", f"capability manifest {path.name} must be a mapping")
    try:
        validate_contract("capability-manifest", loaded)
    except ContractValidationError as error:
        raise ToolError(
            "CONTRACT_INVALID",
            f"capability manifest {path.name} failed schema validation: {error}",
        ) from error
    return loaded


class CapabilityRegistry:
    """Validated capability registry.  Health checks are lazy and TTL-cached."""

    def __init__(
        self,
        capabilities_dir: Path | None = None,
        *,
        environment: Environment | None = None,
        health_ttl_seconds: int = 60,
        http_transport: HttpTransport | None = None,
        probe_on_load: bool = True,
    ) -> None:
        self.capabilities_dir = capabilities_dir or default_capabilities_dir()
        self.environment = environment or Environment()
        self.health_ttl_seconds = health_ttl_seconds
        self.http_transport = http_transport
        self.manifests: dict[str, dict[str, Any]] = {}
        self.aliases: dict[str, str] = dict(ID_BY_ALIAS)
        self.adapters: dict[str, ToolAdapter] = {}
        self.detections: dict[str, DetectionResult] = {}
        self.experimental_enabled: frozenset[str] = frozenset()
        self._health: dict[str, tuple[float, HealthResult]] = {}
        self._load()
        if probe_on_load:
            asyncio.run(self._probe_all())

    def _load(self) -> None:
        if not self.capabilities_dir.is_dir():
            raise ToolError(UNAVAILABLE, f"capabilities directory missing: {self.capabilities_dir}")
        files = sorted(self.capabilities_dir.glob("*.yaml"))
        if len(files) < 4:
            raise ToolError(UNAVAILABLE, "expected four capability manifests")
        for path in files:
            manifest = load_manifest_file(path)
            capability_id = str(manifest["capability_id"])
            triggers = manifest.get("triggers")
            alias = str(triggers[0]) if isinstance(triggers, list) and triggers else capability_id
            self.manifests[capability_id] = manifest
            self.aliases[alias] = capability_id
            self.aliases[capability_id] = capability_id
            if alias not in KNOWN_ALIASES:
                raise ToolError("CONTRACT_INVALID", f"no adapter registered for {alias}")
            adapter = _build_adapter(alias, manifest, self.environment, self.http_transport)
            if isinstance(adapter, ExperimentalAdapter):
                adapter.experimental = True
                adapter.enabled = alias in self.experimental_enabled
            self.adapters[capability_id] = adapter
            self.adapters[alias] = adapter

    async def _probe_all(self) -> None:
        for capability_id, adapter in list(self.adapters.items()):
            if capability_id not in self.manifests:
                continue
            self.detections[capability_id] = await adapter.detect(self.environment)

    def resolve_id(self, capability_id: str) -> str:
        if capability_id in self.aliases:
            return self.aliases[capability_id]
        raise ToolError(UNAVAILABLE, f"unknown capability {capability_id!r}")

    def get_adapter(self, capability_id: str, *, require_available: bool = True) -> ToolAdapter:
        resolved = self.resolve_id(capability_id)
        adapter = self.adapters.get(resolved)
        if adapter is None:
            raise ToolError(UNAVAILABLE, f"unknown capability {capability_id!r}")
        if require_available:
            detection = self.detections.get(resolved)
            if detection is None or detection.status != "available":
                status = detection.status if detection is not None else "unverified"
                raise ToolError(
                    UNAVAILABLE,
                    f"capability {capability_id} is {status}",
                    details={"status": status},
                )
        return adapter

    def list_capabilities(self, *, include_experimental: bool = False) -> list[CapabilityStatus]:
        items: list[CapabilityStatus] = []
        for capability_id, manifest in self.manifests.items():
            detection = self.detections.get(capability_id)
            triggers = manifest.get("triggers") or [capability_id]
            alias = str(triggers[0])
            if alias in EXPERIMENTAL_ALIASES and not include_experimental:
                continue
            status = detection.status if detection is not None else "unverified"
            items.append(
                CapabilityStatus(
                    capability_id=capability_id,
                    alias=alias,
                    kind=str(manifest.get("kind")),
                    status=status,
                    version_expected=str(manifest.get("version")),
                    version_observed=detection.version if detection else None,
                    evidence_ceiling=str(manifest.get("evidence_ceiling")),
                    detail=detection.detail if detection else "not probed",
                    executable=detection.executable if detection else None,
                )
            )
        return items

    async def detect(self, capability_id: str) -> DetectionResult:
        adapter = self.get_adapter(capability_id, require_available=False)
        resolved = self.resolve_id(capability_id)
        result = await adapter.detect(self.environment)
        self.detections[resolved] = result
        return result

    async def health(self, capability_id: str) -> HealthResult:
        resolved = self.resolve_id(capability_id)
        cached = self._health.get(resolved)
        now = time.monotonic()
        if cached and cached[0] > now:
            return cached[1]
        adapter = self.get_adapter(capability_id, require_available=False)
        result = await adapter.health(self.environment)
        self._health[resolved] = (now + self.health_ttl_seconds, result)
        return result


def iter_manifest_paths(directory: Path | None = None) -> Iterable[Path]:
    root = directory or default_capabilities_dir()
    return sorted(root.glob("*.yaml"))
