"""Normalized Global knowledge models (blueprint §7.2)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

RECORD_TYPES = (
    "mechanism",
    "incident",
    "tool",
    "method",
    "false_positive_trap",
    "fix",
    "evaluation_result",
    "finding_pattern",
    "specialist_skill",
    "reasoning_lens",
)
RecordType = Literal[
    "mechanism",
    "incident",
    "tool",
    "method",
    "false_positive_trap",
    "fix",
    "evaluation_result",
    "finding_pattern",
    "specialist_skill",
    "reasoning_lens",
]
NODE_TYPE_BY_RECORD: dict[str, str] = {
    "mechanism": "MechanismCard",
    "incident": "IncidentCard",
    "tool": "ToolCard",
    "method": "MethodCard",
    "false_positive_trap": "FalsePositiveTrap",
    "fix": "FixCard",
    "evaluation_result": "EvaluationResult",
    "finding_pattern": "VulnerabilityPattern",
    "specialist_skill": "SpecialistSkill",
    "reasoning_lens": "ReasoningLens",
}


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None and str(item) != ""]
    return [str(value)]


class LicenseInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spdx_id: str
    attribution_required: bool = True
    local_use: bool = True
    redistribution: bool = False
    retention_constraint: str = "none"


class SourcePin(BaseModel):
    model_config = ConfigDict(extra="forbid")
    commit: str = ""
    tag: str = ""
    archive_sha256: str = ""


class SourceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str
    origin: str = ""
    commit_or_version: str = ""
    pin: SourcePin = Field(default_factory=SourcePin)
    locator: str = ""
    retrieved_at: str = ""


class SourceRegistryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str
    display_name: str
    source_type: Literal["repository", "api", "document", "derived_methodology"] = "repository"
    origin: str
    pin: SourcePin = Field(default_factory=SourcePin)
    license: LicenseInfo
    trust_tier: str = "curated_external"
    reproduction_status: str = "unverified"
    contamination_flags: list[str] = Field(default_factory=list)
    contamination_registry: Literal["production", "development_evaluation", "sealed_holdout"] = (
        "production"
    )
    phase: Literal[
        "proposed",
        "deferred",
        "catalogued",
        "ingested",
        "active",
        "quarantined",
        "tombstoned",
    ] = "proposed"
    authors: list[str] = Field(default_factory=list)
    notes: str = ""


class TombstoneRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str
    reason: str
    tombstoned_at: str
    previous_phase: str = "active"


class QuarantineRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str
    stage: str
    reason: str
    raw_hash: str = ""
    locator: str = ""
    created_at: str


class KnowledgeRecord(BaseModel):
    """Canonical Global knowledge row. Execution defaults false; retrieval requires provenance."""

    model_config = ConfigDict(extra="forbid")
    record_id: str
    record_type: RecordType
    source_ref: SourceRef
    authors: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    commit_or_version: str = ""
    date: datetime
    raw_hash: str
    parser_version: str
    license_info: LicenseInfo
    title: str = ""
    summary: str = ""
    citation: str | None = None
    language: str | None = None
    chain: str | None = None
    framework: str | None = None
    compiler: str | None = None
    protocol: str | None = None
    component: str | None = None
    mechanism: str | None = None
    invariant: str | None = None
    preconditions: list[str] = Field(default_factory=list)
    attacker_capability: str | None = None
    attack_steps: list[str] = Field(default_factory=list)
    impact: str | None = None
    fix: str | None = None
    code_signals: list[str] = Field(default_factory=list)
    api_signals: list[str] = Field(default_factory=list)
    applicability_predicates: list[str] = Field(default_factory=list)
    non_applicability: list[str] = Field(default_factory=list)
    false_positive_conditions: list[str] = Field(default_factory=list)
    trust_tier: str = "curated_external"
    completeness: float = 0.5
    conflicts: list[str] = Field(default_factory=list)
    reproduction_status: str = "unverified"
    safe_for_retrieval: bool = True
    safe_for_execution: bool = False
    hard_negatives: list[str] = Field(default_factory=list)
    hard_negative: bool = False
    benchmark_exposure: list[str] = Field(default_factory=list)
    near_duplicate_lineage: list[str] = Field(default_factory=list)
    questions: list[str] = Field(default_factory=list)
    required_artifacts: list[str] = Field(default_factory=list)
    stop_conditions: list[str] = Field(default_factory=list)
    false_positive_traps: list[str] = Field(default_factory=list)
    role_description: str | None = None
    knowledge_policy: str | None = None
    token_budget: int | None = None
    root_cause: str | None = None
    attack_path: list[str] = Field(default_factory=list)
    symptoms: list[str] = Field(default_factory=list)
    affected_protocols: list[str] = Field(default_factory=list)
    why_safe: str | None = None
    distinction: str | None = None
    safe_variant_code: str | None = None
    canonical_key: str | None = None
    taxonomy: list[str] = Field(default_factory=list)
    variant_of: str | None = None
    learned_from: str | None = None
    contradiction_group: str | None = None

    @field_validator("completeness", mode="before")
    @classmethod
    def _completeness(cls, value: Any) -> float:
        if value is None or value == "":
            return 0.5
        return float(value)

    @field_validator(
        "authors",
        "urls",
        "preconditions",
        "attack_steps",
        "code_signals",
        "api_signals",
        "applicability_predicates",
        "non_applicability",
        "false_positive_conditions",
        "conflicts",
        "hard_negatives",
        "benchmark_exposure",
        "near_duplicate_lineage",
        "questions",
        "required_artifacts",
        "stop_conditions",
        "false_positive_traps",
        "attack_path",
        "symptoms",
        "affected_protocols",
        "taxonomy",
        mode="before",
    )
    @classmethod
    def _lists(cls, value: Any) -> list[str]:
        return _as_str_list(value)

    @field_validator("date", mode="before")
    @classmethod
    def _date(cls, value: Any) -> datetime:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=UTC)
            return value
        text = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed

    @field_serializer("date")
    def _dump_date(self, value: datetime) -> str:
        utc = value.astimezone(UTC).replace(microsecond=0)
        return utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    def canonical_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class MechanismCard(KnowledgeRecord):
    record_type: Literal["mechanism", "reasoning_lens"] = "mechanism"


class IncidentCard(KnowledgeRecord):
    record_type: Literal["incident"] = "incident"


class SpecialistSkill(KnowledgeRecord):
    record_type: Literal["specialist_skill"] = "specialist_skill"


def record_from_mapping(payload: dict[str, Any]) -> KnowledgeRecord:
    kind = str(payload.get("record_type") or "mechanism")
    if kind == "incident":
        return IncidentCard.model_validate(payload)
    if kind == "specialist_skill":
        return SpecialistSkill.model_validate(payload)
    if kind in {"mechanism", "reasoning_lens"}:
        return MechanismCard.model_validate(payload)
    return KnowledgeRecord.model_validate(payload)
