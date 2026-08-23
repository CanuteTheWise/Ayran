"""Blind adjudication forms, rubric scores, and inter-rater agreement."""

from __future__ import annotations

from typing import Any

from ayran.context.ids import content_id
from ayran.evaluation.models import AdjudicationForm, AgreementReport, ArmRun
from ayran.evaluation.paths import PINNED_TIME, RUBRIC_VERSION
from ayran.graph.canonical import canonical_hash

DEFAULT_JUDGES = ("judge_alpha", "judge_beta")

RUBRIC_AXES = (
    "severity_weighted_recall",
    "precision",
    "false_positive_rate",
    "executable_poc_rate",
    "defect_pinning_rate",
)


def _scores_from_run(run: ArmRun) -> dict[str, float]:
    primary = run.metrics
    scores: dict[str, float] = {}
    if primary.severity_weighted_recall is not None:
        scores["severity_weighted_recall"] = primary.severity_weighted_recall
    if primary.precision is not None:
        scores["precision"] = primary.precision
    if primary.false_positive_rate is not None:
        scores["false_positive_rate"] = 1.0 - primary.false_positive_rate
    if primary.executable_poc_rate is not None:
        scores["executable_poc_rate"] = primary.executable_poc_rate
    if primary.defect_pinning_rate is not None:
        scores["defect_pinning_rate"] = primary.defect_pinning_rate
    return scores


def adjudicate_arm(
    run: ArmRun,
    *,
    session_id: str,
    judge_id: str,
    created_at: str = PINNED_TIME,
) -> AdjudicationForm:
    scores = _scores_from_run(run)
    form_id = content_id("adj", session_id, run.arm, str(run.seed), judge_id)
    unsigned = {
        "form_id": form_id,
        "session_id": session_id,
        "arm": run.arm,
        "seed": run.seed,
        "judge_id": judge_id,
        "rubric_version": RUBRIC_VERSION,
        "scores": scores,
        "created_at": created_at,
    }
    return AdjudicationForm(
        form_id=form_id,
        session_id=session_id,
        arm=run.arm,
        seed=run.seed,
        judge_id=judge_id,
        rubric_version=RUBRIC_VERSION,
        blinded=True,
        scores=scores,
        notes="arm identity withheld from the judge payload",
        content_hash=canonical_hash(unsigned),
    )


def cohen_kappa(left: list[int], right: list[int]) -> float:
    if not left or len(left) != len(right):
        return 1.0
    n = len(left)
    agree = sum(1 for a, b in zip(left, right, strict=True) if a == b) / n
    p_left = sum(left) / n
    p_right = sum(right) / n
    chance = p_left * p_right + (1 - p_left) * (1 - p_right)
    if chance >= 1.0:
        return 1.0
    return round((agree - chance) / (1.0 - chance), 4)


def agreement_report(forms: list[AdjudicationForm]) -> list[AgreementReport]:
    by_judge: dict[str, list[AdjudicationForm]] = {}
    for form in forms:
        by_judge.setdefault(form.judge_id, []).append(form)
    judges = sorted(by_judge)
    reports: list[AgreementReport] = []
    if len(judges) < 2:
        return reports
    left_id, right_id = judges[0], judges[1]
    left = sorted(by_judge[left_id], key=lambda item: (item.arm, item.seed))
    right = sorted(by_judge[right_id], key=lambda item: (item.arm, item.seed))
    labels_l = [1 if item.scores.get("precision", 0) >= 0.8 else 0 for item in left]
    labels_r = [1 if item.scores.get("precision", 0) >= 0.8 else 0 for item in right]
    n = min(len(labels_l), len(labels_r))
    abs_agree = (
        sum(1 for a, b in zip(labels_l[:n], labels_r[:n], strict=True) if a == b) / n if n else 1.0
    )
    reports.append(
        AgreementReport(
            pair=(left_id, right_id),
            cohen_kappa=cohen_kappa(labels_l[:n], labels_r[:n]),
            absolute_agreement=round(abs_agree, 4),
            disagreements=round((1 - abs_agree) * n),
        )
    )
    return reports


def adjudicate_session(
    arms: list[ArmRun],
    *,
    session_id: str,
    judges: tuple[str, ...] = DEFAULT_JUDGES,
) -> tuple[list[AdjudicationForm], list[AgreementReport]]:
    forms = [
        adjudicate_arm(run, session_id=session_id, judge_id=judge)
        for run in arms
        for judge in judges
    ]
    return forms, agreement_report(forms)


def rubric_payload() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "rubric_version": RUBRIC_VERSION,
        "axes": list(RUBRIC_AXES),
        "blinded": True,
        "arm_identity_withheld": True,
    }
