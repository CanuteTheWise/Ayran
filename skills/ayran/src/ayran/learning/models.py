"""Internal Learning Graph records. Durable copies persist as graph-nodes."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

OutcomeType = Literal[
    "accepted",
    "rejected",
    "duplicate",
    "adjudicated",
    "falsified",
    "validated",
    "inconclusive",
    "unsafe",
]
PromotionStage = Literal[
    "captured",
    "quarantined",
    "in_review",
    "approved",
    "generalized",
    "fixtures_ready",
    "contamination_checked",
    "evaluated",
    "released",
    "rejected",
    "archived",
    "rolled_back",
]
ReviewVerdict = Literal["approve", "reject", "needs_revision"]
ReviewerType = Literal["human", "independent_agent"]
RedactionStatus = Literal["clean", "redacted", "incomplete"]
ContaminationStatus = Literal["clean", "overlap", "unknown"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolRunSummary(_Strict):
    capability: str = ""
    duration_ms: int = 0
    resource_usage: dict[str, int] = Field(default_factory=dict)
    output_hash: str = ""
    experimental: bool = False


class RetrievalUsefulness(_Strict):
    record_ids: list[str] = Field(default_factory=list)
    influenced: bool = False
    notes: str = ""


class PhaseMetrics(_Strict):
    phase: str
    runtime_ms: int = 0
    tokens: int = 0
    cost_micros: int = 0


class RightsRecord(_Strict):
    license_or_terms: str = "ayran-internal-learning"
    redistribution_allowed: bool = False
    reviewed: bool = False


class LearningOutcome(_Strict):
    outcome_id: str
    created_at: str
    run_id: str
    outcome_type: OutcomeType
    hypothesis_id: str = ""
    promotion_stage: PromotionStage = "quarantined"
    gate_verdicts: list[dict[str, Any]] = Field(default_factory=list)
    tool_runs: list[ToolRunSummary] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    retrieval: RetrievalUsefulness = Field(default_factory=RetrievalUsefulness)
    false_positive_reason: str = ""
    false_negative_reason: str = ""
    metrics: list[PhaseMetrics] = Field(default_factory=list)
    model_versions: dict[str, str] = Field(default_factory=dict)
    tool_versions: dict[str, str] = Field(default_factory=dict)
    knowledge_versions: dict[str, str] = Field(default_factory=dict)
    corpus_pin: str = ""
    routing_pin: str = ""
    content_hash: str = ""
    rights: RightsRecord = Field(default_factory=RightsRecord)
    contamination_class: str = "development"
    target_identity_hash: str = ""
    claim_digest: str = ""
    origin: str = ""
    novelty_score: float = 0.0
    severity_score: float = 0.0
    cost_to_validate: float = 1.0
    adjudication: str = ""


class TestFixture(_Strict):
    fixture_id: str
    fixture_type: Literal["positive", "hard_negative"]
    code: str
    why_safe: str = ""
    distinction: str = ""
    mechanism: str = ""
    content_hash: str = ""


class LearningCandidate(_Strict):
    candidate_id: str
    created_at: str
    outcome_ref: str
    generalized_mechanism: str
    normalized_pattern: str
    applicability_predicates: list[str] = Field(default_factory=list)
    hard_negatives: list[str] = Field(default_factory=list)
    positive_test_fixtures: list[str] = Field(default_factory=list)
    target_secret_redaction_status: RedactionStatus = "redacted"
    contamination_check_status: ContaminationStatus = "unknown"
    promotion_stage: PromotionStage = "generalized"
    trust_class: str = "model_observation"
    project_families: list[str] = Field(default_factory=list)
    root_cause: str = ""
    seed: str = "0"
    content_hash: str = ""
    rights: RightsRecord = Field(default_factory=RightsRecord)
    provenance_attached: bool = True
    bounded_cost: bool = True


class LearningReview(_Strict):
    review_id: str
    candidate_id: str
    reviewer_id: str
    reviewer_type: ReviewerType
    verdict: ReviewVerdict
    notes: str = ""
    signed_at: str
    content_hash: str = ""


class QuarantineRecord(_Strict):
    quarantine_id: str
    subject_id: str
    subject_kind: Literal["outcome", "candidate"] = "outcome"
    reason: str
    created_at: str
    review_deadline: str
    status: Literal["queued", "in_review", "approved", "rejected", "archived"] = "queued"
    novelty_score: float = 0.0
    severity_score: float = 0.0
    cost_to_validate: float = 1.0
    queue_score: float = 0.0
    inspectable: bool = True
    production_retrievable: bool = False


class AblationResult(_Strict):
    evaluation_id: str
    passed: bool
    result_hash: str
    project_families: int = 0
    baseline: dict[str, float] = Field(default_factory=dict)
    treatment: dict[str, float] = Field(default_factory=dict)
    primary_metric: str = "retrieval_usefulness"
    relative_improvement: float = 0.0
    precision_delta: float = 0.0
    safety_value: bool = False
    notes: str = ""


class RoutingPolicy(_Strict):
    policy_id: str
    created_at: str
    status: Literal["baseline", "active", "superseded", "rolled_back"] = "baseline"
    driver_weights: dict[str, int] = Field(default_factory=dict)
    adapter_weights: dict[str, float] = Field(default_factory=dict)
    knowledge_records: list[str] = Field(default_factory=list)
    content_hash: str = ""
    prior_pointer: str = ""
    rollback_pointer: str = ""


class PromotionRelease(_Strict):
    release_id: str
    created_at: str
    candidates: list[str] = Field(default_factory=list)
    prior_pointer: str = ""
    rollback_pointer: str = ""
    signed_at: str = ""
    ablation_results: list[AblationResult] = Field(default_factory=list)
    reviewer_signatures: list[str] = Field(default_factory=list)
    routing_policy_id: str = ""
    content_hash: str = ""
    signature: str = ""
    action: Literal["promote", "rollback"] = "promote"
    corpus_pin: str = ""


class RollbackResult(_Strict):
    release_id: str
    restored_pointer: str
    rollback_release_id: str
    signed_at: str
    content_hash: str = ""
    historical_pins_retained: bool = True
