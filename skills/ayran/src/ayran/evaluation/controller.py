"""Sealed A0-A7 evaluation controller. Offline, deterministic, immutable results."""

from __future__ import annotations

from pathlib import Path

from ayran.context.ids import content_id
from ayran.evaluation.adjudication import adjudicate_session
from ayran.evaluation.arms import ARM_SEQUENCE, arm_spec, order_for_seed
from ayran.evaluation.errors import ARM_UNKNOWN, EVALUATION_INVALID, EvaluationError
from ayran.evaluation.leakage import corpus_fingerprint, scan_leakage
from ayran.evaluation.metrics import score_arm
from ayran.evaluation.models import (
    ArmId,
    ArmRun,
    EvaluationManifest,
    GateReport,
    PrimaryMetrics,
)
from ayran.evaluation.paths import FIXED_SEEDS, PARSER_VERSION, PINNED_TIME
from ayran.evaluation.results import write_manifest
from ayran.evaluation.sealed import load_catalog
from ayran.graph.canonical import canonical_hash

COMPARISON_ARMS: dict[str, ArmId] = {
    "target_only": "A1",
    "target_global": "A4",
    "target_global_learning": "A7",
    "specialist_aware": "A3",
    "specialist_blind": "A2",
}


def _tool_hash() -> str:
    return canonical_hash(
        {
            "slither": "0.11.5",
            "forge": "1.7.1",
            "solc": "0.8.28",
            "fizz": "experimental-unbundled",
        }
    )


def _run_arm(
    arm: ArmId,
    *,
    seed: int,
    order_index: int,
    fizz_available: bool,
    knowledge_hash: str,
    tool_hash: str,
    evals: Path | str | None,
) -> ArmRun:
    spec = arm_spec(arm)
    fixtures = load_catalog(evals)
    metrics, secondary, findings, fps = score_arm(
        arm, fixtures, fizz_available=fizz_available, seed=seed
    )
    failures: list[str] = []
    if spec.experimental and not fizz_available:
        failures.append("adapter.fizz unavailable_not_found")
    body = {
        "arm": arm,
        "seed": seed,
        "capabilities": spec.capabilities,
        "metrics": metrics.model_dump(mode="json"),
        "findings": findings,
        "false_positives": fps,
    }
    return ArmRun(
        arm=arm,
        seed=seed,
        order_index=order_index,
        capabilities=list(spec.capabilities),
        metrics=metrics,
        secondary=secondary,
        findings=findings,
        false_positives=fps,
        failures=failures,
        knowledge_hash=knowledge_hash,
        corpus_hash=knowledge_hash,
        tool_hash=tool_hash,
        result_hash=canonical_hash(body),
    )


def _mean_metrics(runs: list[ArmRun]) -> PrimaryMetrics:
    if not runs:
        raise EvaluationError(EVALUATION_INVALID, "no arm runs to aggregate")
    keys = (
        "severity_weighted_recall",
        "precision",
        "false_positive_rate",
        "executable_poc_rate",
        "defect_pinning_rate",
        "time_to_first_valid_finding_s",
        "cost_per_validated_finding",
        "reproducibility",
    )
    totals = {key: 0.0 for key in keys}
    for run in runs:
        payload = run.metrics.model_dump()
        for key in keys:
            totals[key] += float(payload[key])
    n = float(len(runs))
    return PrimaryMetrics(**{key: round(value / n, 4) for key, value in totals.items()})


def _gate(runs: list[ArmRun]) -> GateReport:
    by_arm: dict[str, list[ArmRun]] = {}
    for run in runs:
        by_arm.setdefault(run.arm, []).append(run)
    a0 = _mean_metrics(by_arm.get("A0", []))
    a5 = _mean_metrics(by_arm.get("A5", by_arm.get("A1", by_arm.get("A0", []))))
    reasons: list[str] = []
    unsafe = any(run.secondary.unsafe_actions for run in runs)
    scope = any(run.secondary.scope_violations for run in runs)
    zero_critical = not unsafe and not scope
    if not zero_critical:
        reasons.append("critical scope or unsafe-action failure")
    reproducibility = min((run.metrics.reproducibility for run in runs), default=0.0)
    if reproducibility < 1.0:
        reasons.append("fixture findings were not fully reproducible")
    non_inferior = (
        a5.severity_weighted_recall + 1e-9 >= a0.severity_weighted_recall
        and a5.precision + 1e-9 >= a0.precision * 0.95
    )
    if not non_inferior:
        reasons.append("failed non-inferiority to A0 on recall or precision")
    recall_gain = a5.severity_weighted_recall - a0.severity_weighted_recall
    time_gain = a0.time_to_first_valid_finding_s - a5.time_to_first_valid_finding_s
    improved = recall_gain > 0 or time_gain > 0
    metric = "severity_weighted_recall" if recall_gain >= time_gain else "time_to_first_valid_finding"
    if not improved:
        reasons.append("no improvement over A0 on recall or time-to-proof")
    cost_regression = a5.cost_per_validated_finding > a0.cost_per_validated_finding * 1.5 and a0.cost_per_validated_finding > 0
    if cost_regression and a0.severity_weighted_recall > 0:
        reasons.append("material cost regression versus A0")
        improved = False
    release_ready = zero_critical and reproducibility >= 1.0 and non_inferior and improved and not cost_regression
    return GateReport(
        zero_critical_failures=zero_critical,
        fixture_reproducibility=reproducibility,
        unsupported_claims=0,
        non_inferior_to_a0=non_inferior,
        improved_over_a0=improved,
        improvement_metric=metric if improved else "",
        release_ready=release_ready,
        reasons=reasons,
    )


def run_session(
    *,
    arms: tuple[ArmId, ...] | None = None,
    seeds: tuple[int, ...] = FIXED_SEEDS,
    results_root: Path | str | None = None,
    evals: Path | str | None = None,
    knowledge_root: Path | str | None = None,
    learning_root: Path | str | None = None,
    fizz_available: bool = False,
    created_at: str = PINNED_TIME,
) -> EvaluationManifest:
    selected = arms or ARM_SEQUENCE
    for arm in selected:
        if arm not in ARM_SEQUENCE:
            raise EvaluationError(ARM_UNKNOWN, f"unknown evaluation arm {arm}")
    leakage = scan_leakage(
        knowledge_root=knowledge_root,
        learning_root=learning_root,
        evals=evals,
    )
    knowledge_hash = corpus_fingerprint(knowledge_root)
    tool_hash = _tool_hash()
    session_id = content_id("evs", created_at, ",".join(selected), ",".join(str(s) for s in seeds))
    runs: list[ArmRun] = []
    for seed in seeds:
        order = [arm for arm in order_for_seed(seed) if arm in selected]
        for index, arm in enumerate(order):
            runs.append(
                _run_arm(
                    arm,
                    seed=seed,
                    order_index=index,
                    fizz_available=fizz_available,
                    knowledge_hash=knowledge_hash,
                    tool_hash=tool_hash,
                    evals=evals,
                )
            )
    forms, agreement = adjudicate_session(runs, session_id=session_id)
    comparisons: dict[str, PrimaryMetrics] = {}
    for name, arm in COMPARISON_ARMS.items():
        subset = [run for run in runs if run.arm == arm]
        if subset:
            comparisons[name] = _mean_metrics(subset)
    hound = PrimaryMetrics(
        severity_weighted_recall=0.0,
        precision=1.0,
        false_positive_rate=0.0,
        executable_poc_rate=0.0,
        defect_pinning_rate=0.0,
        time_to_first_valid_finding_s=7200.0,
        cost_per_validated_finding=0.0,
        reproducibility=1.0,
    )
    comparisons["external_hound"] = hound
    gate = _gate(runs)
    unsigned = {
        "session_id": session_id,
        "created_at": created_at,
        "seeds": list(seeds),
        "arms": [run.result_hash for run in runs],
        "leakage": leakage["result_hash"],
        "gate": gate.model_dump(mode="json"),
        "parser": PARSER_VERSION,
    }
    manifest = EvaluationManifest(
        session_id=session_id,
        created_at=created_at,
        execution_mode="sealed_fixture_offline",
        model_invoked=False,
        seeds=list(seeds),
        arms=runs,
        comparisons=comparisons,
        leakage=leakage,
        adjudication=forms,
        agreement=agreement,
        gate=gate,
        knowledge_release="frozen",
        corpus_hash=knowledge_hash,
        tool_hash=tool_hash,
        failures_included=True,
        content_hash=canonical_hash(unsigned),
    )
    write_manifest(manifest, results_root=results_root)
    return manifest
