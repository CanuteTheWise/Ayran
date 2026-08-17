"""Shared dataclasses and request/result models for the M4 tool adapter plane.

Request/result models are adapter-internal (they are not M0 wire contracts).
Durable ``ToolRun`` records always use the frozen M0 schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

CapabilityStatusName = Literal[
    "available",
    "unavailable_not_found",
    "unavailable_wrong_version",
    "unavailable_broken",
    "unverified",
]

ParseStatusName = Literal["parsed", "partial", "failed", "parser_drift"]
FailureTypeName = Literal[
    "prerequisite",
    "compile",
    "test",
    "timeout",
    "oom",
    "network",
    "rpc",
    "parser_drift",
    "policy",
    "internal",
]

ADAPTER_VERSION = "1.0.0"
PARSER_VERSION = "1.0.0"
DEFAULT_OUTPUT_CAP_BYTES = 50 * 1024 * 1024
TRUNCATED_MARKER = b"\nAYRAN_OUTPUT_TRUNCATED\n"
ZERO_HASH = "sha256:" + "0" * 64
ALLOWLISTED_ENV = ("PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "USER", "LOGNAME")

# Stable M0 Identifier values (Crockford Crockford-32, no I/L/O/U).
CAP_SOLC = "cap_01J4S0C0000000000000000001"
CAP_FOUNDRY = "cap_01J4F0RG000000000000000001"
CAP_SLITHER = "cap_01J4S1TH000000000000000001"
CAP_SOLODIT = "cap_01J4S0DT000000000000000001"
CAP_FIZZ = "cap_01J4F1ZZ000000000000000001"
CAP_ITYFUZZ = "cap_01J4TYFZ000000000000000001"
CAP_ECHIDNA = "cap_01J4ECHD000000000000000001"
CAP_MEDUSA = "cap_01J4MEDS000000000000000001"
CAP_HALMOS = "cap_01J4HA1M000000000000000001"
PRV_SOLC = "prv_01J4S0C0000000000000000001"
PRV_FOUNDRY = "prv_01J4F0RG000000000000000001"
PRV_SLITHER = "prv_01J4S1TH000000000000000001"
PRV_SOLODIT = "prv_01J4S0DT000000000000000001"
PRV_FIZZ = "prv_01J4F1ZZ000000000000000001"
PRV_ITYFUZZ = "prv_01J4TYFZ000000000000000001"
PRV_ECHIDNA = "prv_01J4ECHD000000000000000001"
PRV_MEDUSA = "prv_01J4MEDS000000000000000001"
PRV_HALMOS = "prv_01J4HA1M000000000000000001"

ALIAS_SOLC = "solc.compile"
ALIAS_FOUNDRY = "foundry.test"
ALIAS_SLITHER = "slither.analyze"
ALIAS_SOLODIT = "solodit.search"
ALIAS_FIZZ = "fizz.harness"
ALIAS_ITYFUZZ = "ityfuzz.hybrid"
ALIAS_ECHIDNA = "echidna.fuzz"
ALIAS_MEDUSA = "medusa.fuzz"
ALIAS_HALMOS = "halmos.symbolic"

ALIAS_BY_ID = {
    CAP_SOLC: ALIAS_SOLC,
    CAP_FOUNDRY: ALIAS_FOUNDRY,
    CAP_SLITHER: ALIAS_SLITHER,
    CAP_SOLODIT: ALIAS_SOLODIT,
    CAP_FIZZ: ALIAS_FIZZ,
    CAP_ITYFUZZ: ALIAS_ITYFUZZ,
    CAP_ECHIDNA: ALIAS_ECHIDNA,
    CAP_MEDUSA: ALIAS_MEDUSA,
    CAP_HALMOS: ALIAS_HALMOS,
}
ID_BY_ALIAS = {alias: cap for cap, alias in ALIAS_BY_ID.items()}
DEFAULT_ALIASES = {ALIAS_SOLC, ALIAS_FOUNDRY, ALIAS_SLITHER, ALIAS_SOLODIT}
EXPERIMENTAL_ALIASES = {ALIAS_FIZZ, ALIAS_ITYFUZZ, ALIAS_ECHIDNA, ALIAS_MEDUSA, ALIAS_HALMOS}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SolcCompileRequest(_Strict):
    source_paths: list[str] = Field(min_length=1)
    output_dir: str | None = None
    optimize: bool = True
    combined_json: bool = True
    pragma_constraint: str | None = None


class SolcContractSummary(_Strict):
    name: str
    bytecode_size: int | None = None
    abi_hash: str | None = None


class SolcCompileResult(_Strict):
    compiler_version: str
    contracts: list[SolcContractSummary]
    warnings: list[str]
    errors: list[str]
    resolved_version: str | None = None
    evidence_ceiling: Literal["observed"] = "observed"


class FoundryRunRequest(_Strict):
    project_root: str
    match_test: str | None = None
    match_path: str | None = None
    fork_url_ref: str | None = None
    fork_block: int | None = None
    seed: int | None = None
    json_output: bool = True


class FoundryTestCase(_Strict):
    name: str
    contract: str
    status: Literal["pass", "fail", "skip"]
    gas: int | None = None
    reason: str | None = None
    traces_present: bool = False


class FoundryBuildDiscovery(_Strict):
    foundry_toml: bool
    remappings_txt: bool
    lib_dir: bool
    config_hash: str
    remappings: list[str]


class FoundryRunResult(_Strict):
    forge_version: str
    solc_version: str | None = None
    compile_error: bool
    tests: list[FoundryTestCase]
    passed: int
    failed: int
    skipped: int
    build: FoundryBuildDiscovery | None = None
    fork_identity_hash: str | None = None
    seed: int | None = None
    evidence_ceiling: Literal["observed"] = "observed"


class SlitherRunRequest(_Strict):
    source_paths: list[str] = Field(min_length=1)
    output_file: str | None = None
    target_root: str | None = None
    detectors: list[str] | None = None


class SlitherSpan(_Strict):
    file: str
    line: int | None = None
    column: int | None = None


class SlitherAlert(_Strict):
    check: str
    severity: str
    confidence: str
    description: str
    spans: list[SlitherSpan]
    classification: Literal["alert_lead", "known_false_positive_pattern"]
    evidence_grade: Literal["lead"] = "lead"


class SlitherCompilationFact(_Strict):
    kind: str
    detail: str
    evidence_grade: Literal["observed"] = "observed"


class SlitherRunResult(_Strict):
    slither_version: str
    alerts: list[SlitherAlert]
    compilation_facts: list[SlitherCompilationFact]
    compile_error: bool
    evidence_ceiling: Literal["lead"] = "lead"


class SoloditSearchRequest(_Strict):
    query: str = Field(min_length=1, max_length=256)
    page: int = Field(default=1, ge=1, le=1000)
    page_size: int = Field(default=20, ge=1, le=100)
    cursor: str | None = None
    category: str | None = None
    severity: str | None = None


class SoloditRecord(_Strict):
    title: str
    severity: str | None = None
    category: str | None = None
    protocol: str | None = None
    source_url: str
    record_id: str
    retrieved_at: str
    evidence_grade: Literal["lead"] = "lead"


class SoloditSearchResult(_Strict):
    query_hash: str
    records: list[SoloditRecord]
    page: int
    next_cursor: str | None = None
    provider_terms: str
    cache_hit: bool = False
    evidence_ceiling: Literal["lead"] = "lead"


@dataclass(slots=True)
class Environment:
    path: str | None = None
    home: Path | None = None
    tmpdir: Path | None = None
    extra_env: dict[str, str] = field(default_factory=dict)
    allowed_binary_roots: tuple[Path, ...] = ()
    extra_env_allowlist: tuple[str, ...] = ()
    solodit_endpoint: str | None = None
    probe_http: bool = False
    which_override: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class DetectionResult:
    capability_id: str
    alias: str
    status: CapabilityStatusName
    executable: str | None
    resolved_realpath: str | None
    version: str | None
    version_output_hash: str | None
    executable_hash: str | None
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "capability_id": self.capability_id,
            "alias": self.alias,
            "status": self.status,
            "executable": self.executable,
            "resolved_realpath": self.resolved_realpath,
            "version": self.version,
            "version_output_hash": self.version_output_hash,
            "executable_hash": self.executable_hash,
            "detail": self.detail,
        }


@dataclass(slots=True)
class HealthResult:
    capability_id: str
    alias: str
    status: CapabilityStatusName
    healthy: bool
    detail: str
    version: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "capability_id": self.capability_id,
            "alias": self.alias,
            "status": self.status,
            "healthy": self.healthy,
            "version": self.version,
            "detail": self.detail,
        }


@dataclass(slots=True)
class CapabilityStatus:
    capability_id: str
    alias: str
    kind: str
    status: CapabilityStatusName
    version_expected: str
    version_observed: str | None
    evidence_ceiling: str
    detail: str
    executable: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "capability_id": self.capability_id,
            "alias": self.alias,
            "kind": self.kind,
            "status": self.status,
            "version_expected": self.version_expected,
            "version_observed": self.version_observed,
            "evidence_ceiling": self.evidence_ceiling,
            "executable": self.executable,
            "detail": self.detail,
        }


@dataclass(slots=True)
class InstallPlan:
    capability_id: str
    alias: str
    tool: str
    version: str
    source: str
    enabled: bool
    expected_artifact_hash: str | None
    install_prefix: str
    disk_mib: int
    memory_mib: int
    cpu: int
    network: str
    dependency_conflicts: list[str]
    rollback_plan: str
    cleanup_plan: str
    drvfs_warning: str | None
    free_ext4_mib: int | None
    blocked_reason: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "capability_id": self.capability_id,
            "alias": self.alias,
            "tool": self.tool,
            "version": self.version,
            "source": self.source,
            "enabled": self.enabled,
            "expected_artifact_hash": self.expected_artifact_hash,
            "install_prefix": self.install_prefix,
            "requirements": {
                "disk_mib": self.disk_mib,
                "memory_mib": self.memory_mib,
                "cpu": self.cpu,
                "network": self.network,
            },
            "dependency_conflicts": list(self.dependency_conflicts),
            "rollback_plan": self.rollback_plan,
            "cleanup_plan": self.cleanup_plan,
            "drvfs_warning": self.drvfs_warning,
            "free_ext4_mib": self.free_ext4_mib,
            "blocked_reason": self.blocked_reason,
        }


@dataclass(slots=True)
class CleanupResult:
    removed_paths: list[str]
    preserved_artifacts: list[str]
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "removed_paths": list(self.removed_paths),
            "preserved_artifacts": list(self.preserved_artifacts),
            "detail": self.detail,
        }


@dataclass(slots=True)
class ExecutionPolicy:
    allowed_paths: tuple[Path, ...] = ()
    network: str = "none"
    allowed_hosts: tuple[str, ...] = ()
    cpu: int = 1
    memory_mib: int = 512
    disk_mib: int = 256
    timeout_seconds: int = 60
    max_output_bytes: int = DEFAULT_OUTPUT_CAP_BYTES
    allow_install: bool = False
    offline: bool = False
    scope_hash: str = ZERO_HASH
    graceful_stop_seconds: float = 2
    allow_experimental: bool = False


@dataclass(slots=True)
class RawRun:
    argv: list[str]
    cwd: str | None
    env_fingerprint: str
    started_at: str
    ended_at: str
    exit_code: int | None
    signal: str | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_hash: str
    stderr_hash: str
    output_file_hashes: dict[str, str]
    input_hashes: list[str]
    executable_hash: str | None
    timeout: bool
    failure_type: FailureTypeName | None
    working_copy: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    truncated: bool = False
    http_status: int | None = None
    privacy_audit: list[dict[str, str]] = field(default_factory=list)
