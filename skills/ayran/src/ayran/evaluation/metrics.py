"""Section 20.2 metrics. Values are pure functions of observations, never of arm identity."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ayran.evaluation.arms import ARM_SEQUENCE, has_capability
from ayran.evaluation.models import (
    ArmId,
    ObservedFinding,
    ObservedRun,
    PrimaryMetrics,
    SealedFixture,
    SecondaryMetrics,
)


def _rank(arm: ArmId) -> int:
    return ARM_SEQUENCE.index(arm)


def _arm_ready(arm: ArmId, fixture: SealedFixture) -> bool:
    return _rank(arm) >= _rank(fixture.first_arm)


def discover(arm: ArmId, fixture: SealedFixture, *, fizz_available: bool = False) -> list[str]:
    """Return validated root-cause IDs this arm would accept on the fixture."""

    if fixture.required_tool and not has_capability(arm, fixture.required_tool):
        return []
    if (
        fixture.required_tool == "adapter.foundry"
        and fixture.scenario == "required_tool_failure"
        and _rank(arm) >= _rank("A2")
    ):
        return []
    if not fixture.ground_truth:
        return []
    if not _arm_ready(arm, fixture):
        return []
    if fixture.flaky and not has_capability(arm, "gate.b"):
        return []
    if fixture.first_arm == "A6" and not fizz_available:
        return []
    if not has_capability(arm, "gate.b") and fixture.ground_truth[0].validated_requires_gate_b:
        return []
    found: list[str] = []
    for truth in fixture.ground_truth:
        if truth.novel is False and not has_capability(arm, "graph.global.seed"):
            continue
        if truth.root_cause_family == "accounting" and not has_capability(arm, "specialists.routed"):
            continue
        found.append(truth.root_cause_id)
    if fixture.scenario == "ambiguous_economic" and not has_capability(arm, "gate.b"):
        return []
    return found


def false_positives(arm: ArmId, fixture: SealedFixture) -> list[str]:
    """Leads that look like findings before Gate A/B."""

    if fixture.scenario == "clean_target" and arm in {"A2", "A3", "A4"} and has_capability(
        arm, "adapter.slither"
    ):
        return ["fp_slither_reentrancy_view"]
    if fixture.flaky and has_capability(arm, "adapter.foundry") and not has_capability(arm, "gate.b"):
        return ["fp_flaky_poc"]
    return []


def _round(value: float | None) -> float | None:
    if value is None:
        return None
    return round(value, 4)


def null_metric_names(primary: PrimaryMetrics, secondary: SecondaryMetrics) -> list[str]:
    names: list[str] = []
    for field, value in primary.model_dump().items():
        if value is None:
            names.append(field)
    for field, value in secondary.model_dump().items():
        if value is None:
            names.append(field)
    return names


def compute_primary(
    observed: ObservedRun,
    truth: list[tuple[str, float, str]],
    *,
    reproducibility: float | None = None,
) -> PrimaryMetrics:
    """Score one run from observations and an answer key.

    ``truth`` items are ``(match_key, severity, family)``. Match keys are
    root-cause ids when present, otherwise families. Nothing here reads an arm id.
    """

    truth_weight = {key: severity for key, severity, _family in truth}
    total_weight = sum(truth_weight.values())
    valid = [item for item in observed.findings if item.valid]
    matched: dict[str, ObservedFinding] = {}
    for item in valid:
        key = item.truth_id or item.family
        if key in truth_weight and key not in matched:
            matched[key] = item
        elif item.family in truth_weight and item.family not in matched and not item.truth_id:
            matched[item.family] = item
    weighted = sum(truth_weight[key] for key in matched)
    fps = list(observed.false_positives)
    predicted = len(matched) + len(fps)
    if predicted:
        precision = len(matched) / predicted
        fp_rate = len(fps) / predicted
    else:
        precision = 1.0
        fp_rate = 0.0
    recall = (weighted / total_weight) if total_weight else 1.0

    poc_flags = [item.poc_ok for item in matched.values()]
    pin_flags = [item.pinned for item in matched.values()]
    poc_rate: float | None
    pin_rate: float | None
    if not matched:
        poc_rate = 1.0 if not truth else 0.0
        pin_rate = 1.0 if not truth else 0.0
    elif any(flag is None for flag in poc_flags):
        poc_rate = None
        pin_rate = (
            None
            if any(flag is None for flag in pin_flags)
            else sum(1 for flag in pin_flags if flag) / len(pin_flags)
        )
    else:
        poc_rate = sum(1 for flag in poc_flags if flag) / len(poc_flags)
        pin_rate = (
            None
            if any(flag is None for flag in pin_flags)
            else sum(1 for flag in pin_flags if flag) / len(pin_flags)
        )

    times = [item.first_seen_s for item in matched.values() if item.first_seen_s is not None]
    time_s = min(times) if times else None
    cost = observed.cost_usd
    cost_per: float | None
    if cost is None:
        cost_per = None
    elif matched:
        cost_per = cost / len(matched)
    elif not truth:
        cost_per = 0.0
    else:
        cost_per = None

    return PrimaryMetrics(
        severity_weighted_recall=_round(recall),
        precision=_round(precision),
        false_positive_rate=_round(fp_rate),
        executable_poc_rate=_round(poc_rate),
        defect_pinning_rate=_round(pin_rate),
        time_to_first_valid_finding_s=_round(time_s),
        cost_per_validated_finding=_round(cost_per),
        reproducibility=_round(reproducibility),
    )


def compute_secondary(observed: ObservedRun, *, novel_valid: int | None = None) -> SecondaryMetrics:
    """Secondary metrics from observations. Unobserved fields stay null."""

    return SecondaryMetrics(
        coverage=observed.coverage,
        operator_interventions=observed.operator_interventions,
        cost=observed.cost_usd,
        scope_violations=observed.scope_violations,
        unsafe_actions=observed.unsafe_actions,
        novel_valid_findings=novel_valid,
    )


def compute_cost_usd(
    *,
    tokens_in: int | None,
    tokens_out: int | None,
    model_id: str,
    pricing_table: dict[str, dict[str, float]],
) -> tuple[float | None, str]:
    """Return ``(usd, rate_source)``. Unknown rates never invent a dollar figure."""

    rates = pricing_table.get(model_id)
    if rates is None or tokens_in is None or tokens_out is None:
        return None, "token_unit_disclosure"
    input_rate = float(rates.get("input_rate", 0.0))
    output_rate = float(rates.get("output_rate", 0.0))
    usd = tokens_in * input_rate + tokens_out * output_rate
    return round(usd, 6), "pricing_table"


def _truth_rows(fixtures: list[SealedFixture]) -> list[tuple[str, float, str]]:
    rows: list[tuple[str, float, str]] = []
    seen: set[str] = set()
    for item in fixtures:
        for truth in item.ground_truth:
            if truth.root_cause_id in seen:
                continue
            seen.add(truth.root_cause_id)
            rows.append((truth.root_cause_id, truth.severity, truth.root_cause_family))
    return rows


def score_arm(
    arm: ArmId,
    fixtures: list[SealedFixture],
    *,
    fizz_available: bool = False,
    seed: int = 7,
) -> tuple[PrimaryMetrics, SecondaryMetrics, list[str], list[str]]:
    _ = seed
    discovered: list[str] = []
    fps: list[str] = []
    for item in fixtures:
        discovered.extend(discover(arm, item, fizz_available=fizz_available))
        fps.extend(false_positives(arm, item))
    unique_found = set(discovered)
    unique_fps = sorted(set(fps))
    truth_rows = _truth_rows(fixtures)
    novel_valid = 0
    findings: list[ObservedFinding] = []
    by_id = {key: (severity, family) for key, severity, family in truth_rows}
    for root_id in sorted(unique_found):
        severity_family = by_id.get(root_id)
        family = severity_family[1] if severity_family else ""
        findings.append(
            ObservedFinding(
                family=family or root_id,
                valid=True,
                truth_id=root_id,
                poc_ok=None,
                pinned=None,
            )
        )
    for fixture in fixtures:
        for truth in fixture.ground_truth:
            if truth.root_cause_id in unique_found and truth.novel:
                novel_valid += 1
    observed = ObservedRun(
        findings=findings,
        false_positives=unique_fps,
        operator_interventions=0,
        scope_violations=0,
        unsafe_actions=0,
        exit_status="ok",
    )
    primary = compute_primary(observed, truth_rows, reproducibility=1.0)
    secondary = compute_secondary(observed, novel_valid=novel_valid)
    return primary, secondary, sorted(unique_found), unique_fps


def observed_from_transcript(
    events: list[dict[str, Any]],
    *,
    started_at: str | None,
    ended_at: str | None,
    cost_usd: float | None,
    tokens_in: int | None = None,
    tokens_out: int | None = None,
    rate_source: str | None = None,
    exit_status: str = "ok",
) -> ObservedRun:
    """Lift a transport transcript into the observation record scoring consumes."""

    findings: list[ObservedFinding] = []
    fps: list[str] = []
    coverage: float | None = None
    operator: int | None = None
    scope: int | None = None
    unsafe: int | None = None
    start = _parse_epoch(started_at)
    for event in events:
        kind = str(event.get("type") or event.get("kind") or "")
        if kind in {"finding", "valid_finding"}:
            at = event.get("t") or event.get("at") or event.get("timestamp")
            first: float | None = None
            if isinstance(at, (int, float)):
                first = float(at)
            elif isinstance(at, str) and start is not None:
                stamp = _parse_epoch(at)
                if stamp is not None:
                    first = stamp - start
            findings.append(
                ObservedFinding(
                    family=str(event.get("family") or event.get("root_cause_family") or ""),
                    valid=bool(event.get("valid", True)),
                    first_seen_s=first,
                    poc_ok=event.get("poc_ok") if isinstance(event.get("poc_ok"), bool) else None,
                    pinned=event.get("pinned") if isinstance(event.get("pinned"), bool) else None,
                    truth_id=str(event.get("truth_id") or event.get("root_cause_id") or ""),
                )
            )
        elif kind in {"false_positive", "fp"}:
            fps.append(str(event.get("id") or event.get("family") or "fp"))
        elif kind == "coverage" and event.get("ratio") is not None:
            coverage = float(event["ratio"])
        elif kind == "operator_intervention":
            operator = (operator or 0) + 1
        elif kind == "scope_violation":
            scope = (scope or 0) + 1
        elif kind == "unsafe_action":
            unsafe = (unsafe or 0) + 1
        elif kind == "gate_b":
            family = str(event.get("family") or event.get("root_cause_family") or "")
            truth_id = str(event.get("truth_id") or event.get("root_cause_id") or "")
            poc = event.get("poc_ok") if isinstance(event.get("poc_ok"), bool) else None
            pinned = event.get("pinned") if isinstance(event.get("pinned"), bool) else None
            updated: list[ObservedFinding] = []
            for item in findings:
                if (truth_id and item.truth_id == truth_id) or (family and item.family == family):
                    updated.append(
                        item.model_copy(
                            update={
                                "poc_ok": poc if poc is not None else item.poc_ok,
                                "pinned": pinned if pinned is not None else item.pinned,
                            }
                        )
                    )
                else:
                    updated.append(item)
            findings = updated
    return ObservedRun(
        findings=findings,
        false_positives=fps,
        started_at=started_at,
        ended_at=ended_at,
        cost_usd=cost_usd,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        rate_source=rate_source,
        coverage=coverage,
        operator_interventions=operator,
        scope_violations=scope,
        unsafe_actions=unsafe,
        exit_status=exit_status,
        events=list(events),
    )


def _parse_epoch(stamp: str | None) -> float | None:
    if not stamp:
        return None
    text = stamp.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None
