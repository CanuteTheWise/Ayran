"""CLI/RPC surface for sealed evaluation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ayran.evaluation.adjudication import adjudicate_session
from ayran.evaluation.arms import ARM_SEQUENCE
from ayran.evaluation.controller import run_session
from ayran.evaluation.errors import ARM_UNKNOWN, SESSION_NOT_FOUND, EvaluationError
from ayran.evaluation.models import ArmId
from ayran.evaluation.paths import FIXED_SEEDS
from ayran.evaluation.results import load_manifest, verify_manifest, write_manifest


def run_arm(
    arm: str,
    *,
    seed: int | None = None,
    results_root: Path | str | None = None,
    evals: Path | str | None = None,
    knowledge_root: Path | str | None = None,
    learning_root: Path | str | None = None,
) -> dict[str, Any]:
    if arm not in ARM_SEQUENCE:
        raise EvaluationError(ARM_UNKNOWN, f"unknown evaluation arm {arm}")
    seeds = (int(seed),) if seed is not None else FIXED_SEEDS
    manifest = run_session(
        arms=(arm,),
        seeds=seeds,
        results_root=results_root,
        evals=evals,
        knowledge_root=knowledge_root,
        learning_root=learning_root,
    )
    return manifest.model_dump(mode="json")


def run_all(
    *,
    seed: int | None = None,
    results_root: Path | str | None = None,
    evals: Path | str | None = None,
    knowledge_root: Path | str | None = None,
    learning_root: Path | str | None = None,
) -> dict[str, Any]:
    seeds = (int(seed),) if seed is not None else FIXED_SEEDS
    manifest = run_session(
        results_root=results_root,
        seeds=seeds,
        evals=evals,
        knowledge_root=knowledge_root,
        learning_root=learning_root,
    )
    return manifest.model_dump(mode="json")


def adjudicate(session_id: str, *, results_root: Path | str | None = None) -> dict[str, Any]:
    manifest = load_manifest(session_id, results_root=results_root)
    forms, agreement = adjudicate_session(list(manifest.arms), session_id=session_id)
    if manifest.adjudication and manifest.agreement:
        from ayran.evaluation.live_runner import render_adjudication_markdown

        return {
            "session_id": session_id,
            "adjudication": [item.model_dump(mode="json") for item in manifest.adjudication],
            "agreement": [item.model_dump(mode="json") for item in manifest.agreement],
            "immutable": True,
            "markdown": render_adjudication_markdown(manifest),
        }
    updated = manifest.model_copy(update={"adjudication": forms, "agreement": agreement})
    try:
        write_manifest(updated, results_root=results_root)
    except EvaluationError as error:
        if error.code != "MANIFEST_IMMUTABLE":
            raise
    from ayran.evaluation.live_runner import render_adjudication_markdown

    return {
        "session_id": session_id,
        "adjudication": [item.model_dump(mode="json") for item in forms],
        "agreement": [item.model_dump(mode="json") for item in agreement],
        "immutable": True,
        "markdown": render_adjudication_markdown(updated),
    }


def results(session_id: str, *, results_root: Path | str | None = None) -> dict[str, Any]:
    if not session_id:
        raise EvaluationError(SESSION_NOT_FOUND, "evaluation results require a session id")
    verify_manifest(session_id, results_root=results_root)
    return load_manifest(session_id, results_root=results_root).model_dump(mode="json")


def parse_arm(value: str) -> ArmId:
    arm = value.strip().upper()
    if arm not in ARM_SEQUENCE:
        raise EvaluationError(ARM_UNKNOWN, f"unknown evaluation arm {value}")
    return arm


def preregister_eval(manifest: Path | str, *, results_root: Path | str) -> dict[str, Any]:
    from ayran.evaluation.preregistration import load_preregistration, preregister

    return preregister(load_preregistration(manifest), results_root=results_root)


def pause_eval(*, results_root: Path | str) -> dict[str, Any]:
    from ayran.evaluation.live_runner import pause_flag_path, write_pause_flag

    path = write_pause_flag(results_root)
    return {"paused": True, "path": str(pause_flag_path(results_root)), "wrote": str(path)}


def run_live(
    *,
    preregistration: Path | str,
    targets: Path | str,
    results_root: Path | str,
    seed: int | None = None,
) -> dict[str, Any]:
    from ayran.evaluation.live_runner import run_live_session
    from ayran.evaluation.preregistration import load_preregistration
    from ayran.evaluation.targets import load_target_dir, select_targets
    from ayran.evaluation.transport import ScriptedArmTransport

    sheet = load_preregistration(preregistration)
    loaded = load_target_dir(targets)
    selected = select_targets(loaded, [])
    manifest = run_live_session(
        preregistration=sheet,
        transport=ScriptedArmTransport(),
        targets=selected,
        cards=[],
        results_root=results_root,
        seeds=(int(seed),) if seed is not None else (7,),
    )
    return manifest.model_dump(mode="json")
