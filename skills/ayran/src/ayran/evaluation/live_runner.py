"""Live evaluation runner: contamination first, then preregistration, then launches."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ayran.context.ids import content_id
from ayran.evaluation.adjudication import adjudicate_session
from ayran.evaluation.arms import ARM_SEQUENCE, arm_spec, order_for_seed
from ayran.evaluation.errors import PAUSE_ACTIVE, EvaluationError
from ayran.evaluation.metrics import (
    compute_cost_usd,
    compute_primary,
    compute_secondary,
    null_metric_names,
    observed_from_transcript,
)
from ayran.evaluation.models import ArmId, ArmRun, EvaluationManifest, GateReport, PrimaryMetrics
from ayran.evaluation.partitions import enforce_at_harness_start
from ayran.evaluation.paths import FIXED_SEEDS, PARSER_VERSION
from ayran.evaluation.preregistration import Preregistration, require_preregistration
from ayran.evaluation.results import write_manifest
from ayran.evaluation.targets import TargetManifest
from ayran.evaluation.transport import ArmSpec, ArmTransport
from ayran.graph.canonical import atomic_write, canonical_hash, utc_now
from ayran.knowledge.models import KnowledgeRecord

PAUSE_FLAG = "eval.pause"
FULL_AYRAN_ARM: ArmId = "A5"


def pause_flag_path(results_root: Path | str) -> Path:
    return Path(results_root) / PAUSE_FLAG


def write_pause_flag(results_root: Path | str) -> Path:
    path = pause_flag_path(results_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("paused_operator\n", encoding="utf-8")
    return path


def pause_is_set(results_root: Path | str) -> bool:
    return pause_flag_path(results_root).is_file()


def _persist(path: Path, payload: Mapping[str, Any]) -> None:
    atomic_write(path, json.dumps(dict(payload), indent=2, sort_keys=True).encode("utf-8"))


def _truth_from_target(target: TargetManifest) -> list[tuple[str, float, str]]:
    return [
        (item.root_cause_family, item.severity, item.root_cause_family)
        for item in target.ground_truth
    ]


def _mean_optional(runs: Sequence[ArmRun]) -> PrimaryMetrics:
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
    counts = {key: 0 for key in keys}
    for run in runs:
        payload = run.metrics.model_dump()
        for key in keys:
            value = payload[key]
            if value is None:
                continue
            totals[key] += float(value)
            counts[key] += 1
    averaged: dict[str, float | None] = {
        key: round(totals[key] / counts[key], 4) if counts[key] else None for key in keys
    }
    return PrimaryMetrics(**averaged)


def _live_gate(runs: list[ArmRun]) -> GateReport:
    by_arm: dict[str, list[ArmRun]] = {}
    for run in runs:
        by_arm.setdefault(run.arm, []).append(run)
    a0_runs = by_arm.get("A0", [])
    full_runs = by_arm.get(FULL_AYRAN_ARM, [])
    reasons: list[str] = []
    unsafe = any(bool(run.secondary.unsafe_actions) for run in runs)
    scope = any(bool(run.secondary.scope_violations) for run in runs)
    zero_critical = not unsafe and not scope
    if not a0_runs or not full_runs:
        reasons.append("A0 vs full-Ayran comparison incomplete")
        return GateReport(
            zero_critical_failures=zero_critical,
            fixture_reproducibility=0.0,
            unsupported_claims=0,
            non_inferior_to_a0=False,
            improved_over_a0=False,
            release_ready=False,
            reasons=reasons,
        )
    a0 = _mean_optional(a0_runs)
    full = _mean_optional(full_runs)
    if a0.severity_weighted_recall is None or full.severity_weighted_recall is None:
        reasons.append("recall unobserved; live comparison not claimed")
        return GateReport(
            zero_critical_failures=zero_critical,
            fixture_reproducibility=1.0,
            unsupported_claims=0,
            non_inferior_to_a0=False,
            improved_over_a0=False,
            release_ready=False,
            reasons=reasons,
        )
    a0_precision = a0.precision if a0.precision is not None else 0.0
    full_precision = full.precision if full.precision is not None else 0.0
    non_inferior = (
        full.severity_weighted_recall + 1e-9 >= a0.severity_weighted_recall
        and full_precision + 1e-9 >= a0_precision * 0.95
    )
    improved = full.severity_weighted_recall > a0.severity_weighted_recall
    if not non_inferior:
        reasons.append("full-Ayran was not non-inferior to A0")
    if not improved:
        reasons.append("full-Ayran did not lift a preregistered primary metric over A0")
    return GateReport(
        zero_critical_failures=zero_critical,
        fixture_reproducibility=1.0,
        unsupported_claims=0,
        non_inferior_to_a0=non_inferior,
        improved_over_a0=improved,
        improvement_metric="severity_weighted_recall" if improved else "",
        release_ready=zero_critical and non_inferior and improved,
        reasons=reasons,
    )


def run_live_session(
    *,
    preregistration: Preregistration,
    transport: ArmTransport,
    targets: Sequence[TargetManifest],
    cards: Iterable[KnowledgeRecord],
    results_root: Path | str,
    seeds: tuple[int, ...] = (7,),
    created_at: str | None = None,
) -> EvaluationManifest:
    """Orchestrate a live (or scripted-live) session.

    Mandatory order: ``enforce_at_harness_start``, then preregistration
    (``PREREGISTRATION_REQUIRED`` if unsigned), then any ``transport.run``.
    The pause flag is read before every launch; an in-flight run finishes
    best-effort.
    """

    root = Path(results_root)
    root.mkdir(parents=True, exist_ok=True)
    names = [item.target_id for item in targets]
    names.extend(item.workspace_path for item in targets)
    enforce_at_harness_start(cards, names)

    stamp = created_at or utc_now()
    if pause_is_set(root):
        raise EvaluationError(PAUSE_ACTIVE, "eval pause flag is set; refusing to launch")
    record = require_preregistration(preregistration, results_root=root, launch_at=stamp)
    selected = tuple(arm for arm in preregistration.arms if arm in ARM_SEQUENCE)
    session_id = content_id(
        "evs",
        stamp,
        ",".join(selected),
        ",".join(item.target_id for item in targets),
        preregistration.content_hash(),
    )
    session_dir = root / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    pricing = {
        key: value.model_dump(mode="json") for key, value in preregistration.pricing_table.items()
    }
    ledger: list[dict[str, Any]] = []
    session_spend = 0.0
    arm_spend: dict[str, float] = {arm: 0.0 for arm in selected}
    runs: list[ArmRun] = []
    status = "completed"
    order_index = 0
    used_seeds = seeds or FIXED_SEEDS

    def over_cap(arm: ArmId, projected: float) -> bool:
        return (
            session_spend + projected >= preregistration.caps.session_usd
            or arm_spend[arm] + projected >= preregistration.caps.per_arm_usd
        )

    halt = False
    for seed in used_seeds:
        if halt:
            break
        order = [arm for arm in order_for_seed(seed) if arm in selected]
        for target in targets:
            if halt:
                break
            for arm in order:
                if pause_is_set(root):
                    status = "paused_operator"
                    halt = True
                    break
                projected = 0.0
                if ledger:
                    last = ledger[-1].get("usd")
                    if isinstance(last, (int, float)):
                        projected = float(last)
                if over_cap(arm, projected):
                    status = "paused_cap"
                    halt = True
                    break
                spec = arm_spec(arm)
                budget = {
                    "per_arm_usd": preregistration.caps.per_arm_usd,
                    "session_usd": preregistration.caps.session_usd,
                    "remaining_session_usd": max(
                        0.0, preregistration.caps.session_usd - session_spend
                    ),
                }
                transcript = transport.run(
                    ArmSpec(arm=arm, capabilities=list(spec.capabilities)),
                    target,
                    budget,
                )
                usd, rate_source = compute_cost_usd(
                    tokens_in=transcript.usage.input_tokens,
                    tokens_out=transcript.usage.output_tokens,
                    model_id=preregistration.model_id,
                    pricing_table=pricing,
                )
                if usd is not None:
                    session_spend += usd
                    arm_spend[arm] += usd
                run_id = f"{session_id}:{arm}:{target.target_id}:{seed}:{order_index}"
                entry = {
                    "run_id": run_id,
                    "tokens": {
                        "input": transcript.usage.input_tokens,
                        "output": transcript.usage.output_tokens,
                    },
                    "rate_source": rate_source,
                    "usd": usd,
                    "arm": arm,
                    "target_id": target.target_id,
                }
                ledger.append(entry)
                dest = session_dir / arm / target.target_id
                dest.mkdir(parents=True, exist_ok=True)
                _persist(dest / "transcript.json", transcript.model_dump(mode="json"))
                _persist(dest / "usage.json", transcript.usage.model_dump(mode="json"))
                observed = observed_from_transcript(
                    transcript.events,
                    started_at=transcript.started_at or None,
                    ended_at=transcript.ended_at or None,
                    cost_usd=usd,
                    tokens_in=transcript.usage.input_tokens,
                    tokens_out=transcript.usage.output_tokens,
                    rate_source=rate_source,
                    exit_status=transcript.exit_status,
                )
                primary = compute_primary(observed, _truth_from_target(target), reproducibility=None)
                secondary = compute_secondary(observed, novel_valid=None)
                nulls = null_metric_names(primary, secondary)
                failures: list[str] = []
                if transcript.exit_status not in {"ok"}:
                    failures.append(transcript.exit_status)
                findings = [item.family for item in observed.findings if item.valid]
                body = {
                    "arm": arm,
                    "seed": seed,
                    "target_id": target.target_id,
                    "metrics": primary.model_dump(mode="json"),
                    "findings": findings,
                    "false_positives": list(observed.false_positives),
                    "exit_status": transcript.exit_status,
                }
                _persist(dest / "scores.json", body)
                _persist(dest / "ledger.json", entry)
                runs.append(
                    ArmRun(
                        arm=arm,
                        seed=seed,
                        order_index=order_index,
                        capabilities=list(spec.capabilities),
                        metrics=primary,
                        secondary=secondary,
                        findings=findings,
                        false_positives=list(observed.false_positives),
                        failures=failures,
                        result_hash=canonical_hash(body),
                        target_id=target.target_id,
                        started_at=transcript.started_at,
                        ended_at=transcript.ended_at,
                        exit_status=transcript.exit_status,
                        usage=transcript.usage.model_dump(mode="json"),
                        null_metrics=nulls,
                    )
                )
                order_index += 1
                if usd is not None and over_cap(arm, 0.0):
                    status = "paused_cap"
                    halt = True
                    break

    forms, agreement = adjudicate_session(runs, session_id=session_id) if runs else ([], [])
    comparisons: dict[str, PrimaryMetrics] = {}
    a0_runs = [run for run in runs if run.arm == "A0"]
    full_runs = [run for run in runs if run.arm == FULL_AYRAN_ARM]
    if a0_runs:
        comparisons["A0"] = _mean_optional(a0_runs)
    if full_runs:
        comparisons["full-Ayran"] = _mean_optional(full_runs)
    disclosures: list[str] = []
    for run in runs:
        for name in run.null_metrics:
            if name not in disclosures:
                disclosures.append(name)
    gate = _live_gate(runs)
    unsigned = {
        "session_id": session_id,
        "created_at": stamp,
        "seeds": list(used_seeds),
        "arms": [run.result_hash for run in runs],
        "preregistration_hash": preregistration.content_hash(),
        "status": status,
        "parser": PARSER_VERSION,
        "gate": gate.model_dump(mode="json"),
    }
    manifest = EvaluationManifest(
        session_id=session_id,
        created_at=stamp,
        execution_mode="live_model",
        model_invoked=True,
        seeds=list(used_seeds),
        arms=runs,
        comparisons=comparisons,
        leakage={"clean": True, "enforced": True},
        adjudication=forms,
        agreement=agreement,
        gate=gate,
        knowledge_release="held_out",
        failures_included=True,
        content_hash=canonical_hash(unsigned),
        status=status,
        null_metric_disclosures=disclosures,
        preregistration_hash=str(record.get("manifest_hash") or preregistration.content_hash()),
        cost_ledger=ledger,
    )
    write_manifest(manifest, results_root=root)
    _persist(session_dir / "cost-ledger.json", {"entries": ledger, "session_usd": session_spend})
    return manifest


def render_adjudication_markdown(manifest: EvaluationManifest) -> str:
    """Markdown summary: per-arm primaries, A0 deltas, failures, nulls, cost vs caps."""

    lines = [
        "# Live evaluation adjudication",
        "",
        f"- session: `{manifest.session_id}`",
        f"- preregistration_hash: `{manifest.preregistration_hash}`",
        f"- execution_mode: `{manifest.execution_mode}`",
        f"- status: `{manifest.status}`",
        f"- model_invoked: `{manifest.model_invoked}`",
        f"- failures_included: `{manifest.failures_included}`",
        "",
        "## Primary metrics by arm",
        "",
    ]
    by_arm: dict[str, list[ArmRun]] = {}
    for run in manifest.arms:
        by_arm.setdefault(run.arm, []).append(run)
    a0 = manifest.comparisons.get("A0")
    for arm in sorted(by_arm):
        mean = _mean_optional(by_arm[arm])
        lines.append(f"### {arm}")
        for key, value in mean.model_dump().items():
            delta = ""
            if a0 is not None and arm != "A0":
                baseline = getattr(a0, key)
                if value is not None and baseline is not None:
                    delta = f" (delta vs A0: {value - baseline:+.4f})"
            shown = "null" if value is None else value
            lines.append(f"- {key}: {shown}{delta}")
        lines.append("")
    lines.append("## Failures")
    lines.append("")
    listed = [
        f"{run.arm}/{run.target_id}: {', '.join(run.failures)}"
        for run in manifest.arms
        if run.failures
    ]
    if listed:
        lines.extend(f"- {item}" for item in listed)
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Null metric disclosures")
    lines.append("")
    if manifest.null_metric_disclosures:
        lines.extend(f"- {name}" for name in manifest.null_metric_disclosures)
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Cost ledger vs caps")
    lines.append("")
    total = 0.0
    known = False
    for entry in manifest.cost_ledger:
        usd = entry.get("usd")
        lines.append(
            f"- {entry.get('run_id')}: usd={usd} rate_source={entry.get('rate_source')} "
            f"tokens={entry.get('tokens')}"
        )
        if isinstance(usd, (int, float)):
            total += float(usd)
            known = True
    if known:
        lines.append(f"- session spend (priced rows): {total:.6f}")
    else:
        lines.append("- session spend: unobserved (token-unit disclosure only)")
    lines.append(f"- preregistration hash this run used: `{manifest.preregistration_hash}`")
    return "\n".join(lines) + "\n"
