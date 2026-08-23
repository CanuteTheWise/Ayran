"""Internal sealed-evaluation records. Result manifests are immutable JSON."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ArmId = Literal["A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7"]
PartitionName = Literal["train", "development", "test"]
ComparisonId = Literal[
    "target_only",
    "target_global",
    "target_global_learning",
    "specialist_aware",
    "specialist_blind",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GroundTruth(_Strict):
    root_cause_id: str
    root_cause_family: str
    severity: float
    novel: bool = True
    validated_requires_gate_b: bool = True


class SealedFixture(_Strict):
    fixture_id: str
    content_hash: str
    project_family: str
    root_cause_family: str
    contamination_group: str
    partition: PartitionName
    scenario: str
    ground_truth: list[GroundTruth] = Field(default_factory=list)
    first_arm: ArmId = "A5"
    optional_tool: str = ""
    required_tool: str = ""
    flaky: bool = False
    resume: bool = False


class ArmSpec(_Strict):
    arm: ArmId
    capabilities: list[str]
    attribution: str
    knowledge_release: str = ""
    learning_policy: str = ""
    experimental: bool = False


class PrimaryMetrics(_Strict):
    severity_weighted_recall: float | None = None
    precision: float | None = None
    false_positive_rate: float | None = None
    executable_poc_rate: float | None = None
    defect_pinning_rate: float | None = None
    time_to_first_valid_finding_s: float | None = None
    cost_per_validated_finding: float | None = None
    reproducibility: float | None = None


class SecondaryMetrics(_Strict):
    duplicate_rate: float | None = None
    coverage: float | None = None
    tool_selection_accuracy: float | None = None
    retrieval_usefulness: float | None = None
    anchoring_resistance: float | None = None
    gate_rejection_accuracy: float | None = None
    resume_recovery_quality: float | None = None
    operator_interventions: int | None = None
    cost: float | None = None
    scope_violations: int | None = None
    unsafe_actions: int | None = None
    novel_valid_findings: int | None = None
    hypothesis_source_diversity: float | None = None


class ObservedFinding(_Strict):
    family: str
    valid: bool = True
    first_seen_s: float | None = None
    poc_ok: bool | None = None
    pinned: bool | None = None
    truth_id: str = ""


class ObservedRun(_Strict):
    findings: list[ObservedFinding] = Field(default_factory=list)
    false_positives: list[str] = Field(default_factory=list)
    started_at: str | None = None
    ended_at: str | None = None
    cost_usd: float | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    rate_source: str | None = None
    coverage: float | None = None
    operator_interventions: int | None = None
    scope_violations: int | None = None
    unsafe_actions: int | None = None
    exit_status: str = "ok"
    events: list[dict[str, Any]] = Field(default_factory=list)


class ArmRun(_Strict):
    arm: ArmId
    seed: int
    order_index: int
    capabilities: list[str]
    metrics: PrimaryMetrics
    secondary: SecondaryMetrics
    findings: list[str] = Field(default_factory=list)
    false_positives: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)
    knowledge_hash: str = ""
    corpus_hash: str = ""
    tool_hash: str = ""
    result_hash: str = ""
    target_id: str = ""
    started_at: str = ""
    ended_at: str = ""
    exit_status: str = "ok"
    usage: dict[str, Any] = Field(default_factory=dict)
    null_metrics: list[str] = Field(default_factory=list)


class AdjudicationForm(_Strict):
    form_id: str
    session_id: str
    arm: ArmId
    seed: int
    judge_id: str
    rubric_version: str
    blinded: bool = True
    scores: dict[str, float] = Field(default_factory=dict)
    notes: str = ""
    content_hash: str = ""


class AgreementReport(_Strict):
    pair: tuple[str, str]
    cohen_kappa: float
    absolute_agreement: float
    disagreements: int = 0


class GateReport(_Strict):
    zero_critical_failures: bool
    fixture_reproducibility: float
    unsupported_claims: int
    non_inferior_to_a0: bool
    improved_over_a0: bool
    improvement_metric: str = ""
    release_ready: bool
    reasons: list[str] = Field(default_factory=list)


class EvaluationManifest(_Strict):
    schema_version: str = "1.0.0"
    session_id: str
    created_at: str
    execution_mode: str = "sealed_fixture_offline"
    model_invoked: bool = False
    seeds: list[int]
    arms: list[ArmRun]
    comparisons: dict[str, PrimaryMetrics] = Field(default_factory=dict)
    leakage: dict[str, Any] = Field(default_factory=dict)
    adjudication: list[AdjudicationForm] = Field(default_factory=list)
    agreement: list[AgreementReport] = Field(default_factory=list)
    gate: GateReport
    knowledge_release: str = ""
    corpus_hash: str = ""
    tool_hash: str = ""
    failures_included: bool = True
    content_hash: str = ""
    status: str = "completed"
    null_metric_disclosures: list[str] = Field(default_factory=list)
    preregistration_hash: str = ""
    cost_ledger: list[dict[str, Any]] = Field(default_factory=list)
