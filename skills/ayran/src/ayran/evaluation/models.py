"""Internal sealed-evaluation records. Result manifests are immutable JSON."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ArmId = Literal["A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7"]
PartitionName = Literal["train", "development", "test"]
ComparisonId = Literal[
    "external_hound",
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
    severity_weighted_recall: float
    precision: float
    false_positive_rate: float
    executable_poc_rate: float
    defect_pinning_rate: float
    time_to_first_valid_finding_s: float
    cost_per_validated_finding: float
    reproducibility: float


class SecondaryMetrics(_Strict):
    duplicate_rate: float = 0.0
    coverage: float = 0.0
    tool_selection_accuracy: float = 0.0
    retrieval_usefulness: float = 0.0
    anchoring_resistance: float = 0.0
    gate_rejection_accuracy: float = 0.0
    resume_recovery_quality: float = 0.0
    operator_interventions: int = 0
    cost: float = 0.0
    scope_violations: int = 0
    unsafe_actions: int = 0
    novel_valid_findings: int = 0
    hypothesis_source_diversity: float = 0.0


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
