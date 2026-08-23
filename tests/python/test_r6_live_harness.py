"""R6 live evaluation harness: preregistration, contamination, caps, pause, honest scoring."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from ayran.evaluation.errors import (
    PREREGISTRATION_MISMATCH,
    PREREGISTRATION_REQUIRED,
    EvaluationError,
)
from ayran.evaluation.live_runner import run_live_session, write_pause_flag
from ayran.evaluation.metrics import compute_cost_usd, compute_primary, observed_from_transcript
from ayran.evaluation.models import PrimaryMetrics
from ayran.evaluation.partitions import ContaminationViolation
from ayran.evaluation.preregistration import EvalCaps, Preregistration, PricingRates, preregister
from ayran.evaluation.targets import TargetGroundTruth, TargetManifest, select_targets
from ayran.evaluation.transport import ArmTranscript, ArmUsage, ScriptedArmTransport
from ayran.knowledge.defihacklabs import contamination_group
from ayran.knowledge.models import IncidentCard, LicenseInfo, SourceRef

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "eval"
SRC_EVAL = (
    Path(__file__).resolve().parents[2] / "skills" / "ayran" / "src" / "ayran" / "evaluation"
)


def _incident(record_id: str, protocol: str, incident: str) -> IncidentCard:
    return IncidentCard(
        record_id=record_id,
        record_type="incident",
        source_ref=SourceRef(source_id="defihacklabs"),
        date=datetime(2026, 1, 1, tzinfo=UTC),
        raw_hash="sha256:" + "0" * 64,
        parser_version="defihacklabs-1.0.0",
        license_info=LicenseInfo(spdx_id="Apache-2.0"),
        contamination_group=contamination_group(protocol, incident),
    )


def _prereg(
    *,
    targets: list[str],
    created_at: str = "2026-08-23T00:00:00Z",
    session_usd: float = 150.0,
    per_arm_usd: float = 50.0,
    model_id: str = "scripted-ci",
    priced: bool = True,
) -> Preregistration:
    table = {}
    if priced:
        table[model_id] = PricingRates(input_rate=0.001, output_rate=0.002)
    return Preregistration(
        arms=["A0", "A5"],
        targets=targets,
        model_id=model_id,
        model_version="0.0.0",
        thinking_level="none",
        pricing_table=table,
        epsilon_non_inferiority=0.0,
        lift_required_on=["severity_weighted_recall"],
        caps=EvalCaps(per_arm_usd=per_arm_usd, session_usd=session_usd),
        created_at=created_at,
    )


def _target(target_id: str, family: str, severity: float) -> TargetManifest:
    return TargetManifest(
        target_id=target_id,
        workspace_path=str(FIXTURES / "minivault"),
        ground_truth=[TargetGroundTruth(root_cause_family=family, severity=severity)],
        revision_or_commit="fixture-r6-v1",
        held_out=True,
    )


def _ok_transcript(*, usd_tokens: tuple[int, int] = (10000, 5000), family: str = "reentrancy") -> ArmTranscript:
    return ArmTranscript(
        events=[
            {
                "type": "finding",
                "family": family,
                "valid": True,
                "t": 12.0,
                "poc_ok": True,
                "pinned": True,
                "truth_id": family,
            }
        ],
        usage=ArmUsage(input_tokens=usd_tokens[0], output_tokens=usd_tokens[1]),
        started_at="2026-08-23T00:00:00Z",
        ended_at="2026-08-23T00:10:00Z",
        exit_status="ok",
    )


def test_launch_without_preregistration_refused(tmp_path: Path) -> None:
    transport = ScriptedArmTransport()
    target = _target("minivault-reentrancy", "reentrancy", 9.0)
    sheet = _prereg(targets=[target.target_id])
    with pytest.raises(EvaluationError) as raised:
        run_live_session(
            preregistration=sheet,
            transport=transport,
            targets=[target],
            cards=[],
            results_root=tmp_path,
        )
    assert raised.value.code == PREREGISTRATION_REQUIRED
    assert transport.invocations == 0


def test_post_signature_edit_refused(tmp_path: Path) -> None:
    transport = ScriptedArmTransport()
    target = _target("minivault-reentrancy", "reentrancy", 9.0)
    sheet = _prereg(targets=[target.target_id], created_at="2026-08-23T00:00:00Z")
    preregister(sheet, results_root=tmp_path, recorded_at="2026-08-23T00:00:00Z")
    edited = sheet.model_copy(update={"thinking_level": "high"})
    with pytest.raises(EvaluationError) as raised:
        run_live_session(
            preregistration=edited,
            transport=transport,
            targets=[target],
            cards=[],
            results_root=tmp_path,
            created_at="2026-08-23T00:01:00Z",
        )
    assert raised.value.code == PREREGISTRATION_MISMATCH
    assert transport.invocations == 0


def test_contamination_gate_runs_first(tmp_path: Path) -> None:
    transport = ScriptedArmTransport()
    target = _target("EulerVault", "reentrancy", 9.0)
    sheet = _prereg(targets=[target.target_id])
    preregister(sheet, results_root=tmp_path, recorded_at="2026-08-23T00:00:00Z")
    cards = [_incident("r-euler-1", "Euler", "Euler")]
    with pytest.raises(ContaminationViolation):
        run_live_session(
            preregistration=sheet,
            transport=transport,
            targets=[target],
            cards=cards,
            results_root=tmp_path,
            created_at="2026-08-23T00:01:00Z",
        )
    assert transport.invocations == 0
    with pytest.raises(ContaminationViolation):
        select_targets([target], cards)


def test_cost_caps_pause_cleanly(tmp_path: Path) -> None:
    usd, source = compute_cost_usd(
        tokens_in=1000, tokens_out=0, model_id="unknown-model", pricing_table={}
    )
    assert usd is None
    assert source == "token_unit_disclosure"

    target = _target("minivault-reentrancy", "reentrancy", 9.0)
    sheet = _prereg(targets=[target.target_id], session_usd=25.0, per_arm_usd=50.0)
    preregister(sheet, results_root=tmp_path, recorded_at="2026-08-23T00:00:00Z")
    transport = ScriptedArmTransport(
        scripts={
            "A0:minivault-reentrancy": _ok_transcript(),
            "A5:minivault-reentrancy": _ok_transcript(),
        }
    )
    manifest = run_live_session(
        preregistration=sheet,
        transport=transport,
        targets=[target],
        cards=[],
        results_root=tmp_path,
        created_at="2026-08-23T00:01:00Z",
    )
    assert manifest.status == "paused_cap"
    assert transport.invocations == 1
    assert manifest.cost_ledger[0]["rate_source"] == "pricing_table"
    assert manifest.cost_ledger[0]["usd"] == pytest.approx(20.0)
    assert sum(1 for item in manifest.cost_ledger if item.get("usd") is not None) == 1


def test_kill_switch_pauses_between_launches(tmp_path: Path) -> None:
    target = _target("minivault-reentrancy", "reentrancy", 9.0)
    sheet = _prereg(targets=[target.target_id], session_usd=150.0)
    preregister(sheet, results_root=tmp_path, recorded_at="2026-08-23T00:00:00Z")

    class PauseAfterFirst(ScriptedArmTransport):
        def run(self, arm, target, budget):  # type: ignore[no-untyped-def]
            result = super().run(arm, target, budget)
            write_pause_flag(tmp_path)
            return result

    transport = PauseAfterFirst(
        scripts={
            "A0:minivault-reentrancy": _ok_transcript(),
            "A5:minivault-reentrancy": _ok_transcript(),
        }
    )
    manifest = run_live_session(
        preregistration=sheet,
        transport=transport,
        targets=[target],
        cards=[],
        results_root=tmp_path,
        created_at="2026-08-23T00:01:00Z",
    )
    assert manifest.status == "paused_operator"
    assert transport.invocations == 1


def test_scoring_matches_hand_computed_values() -> None:
    # Truth: reentrancy 9.0 + accounting 6.0 = 15. Found: reentrancy only.
    # 1 FP. Gate B poc+pin on the one find. First valid at t=12s. Cost 4.0.
    # recall = 9/15 = 0.6; precision = 1/2 = 0.5; fp_rate = 0.5
    # poc = 1.0; pin = 1.0; time = 12.0; cost_per = 4.0
    events = [
        {
            "type": "finding",
            "family": "reentrancy",
            "valid": True,
            "t": 12.0,
            "poc_ok": True,
            "pinned": True,
        },
        {"type": "false_positive", "id": "fp_view"},
    ]
    observed = observed_from_transcript(
        events,
        started_at="2026-08-23T00:00:00Z",
        ended_at="2026-08-23T00:10:00Z",
        cost_usd=4.0,
        exit_status="ok",
    )
    truth = [("reentrancy", 9.0, "reentrancy"), ("accounting", 6.0, "accounting")]
    primary = compute_primary(observed, truth)
    assert primary == PrimaryMetrics(
        severity_weighted_recall=0.6,
        precision=0.5,
        false_positive_rate=0.5,
        executable_poc_rate=1.0,
        defect_pinning_rate=1.0,
        time_to_first_valid_finding_s=12.0,
        cost_per_validated_finding=4.0,
        reproducibility=None,
    )


def test_no_synthetic_metric_rows() -> None:
    forbidden = ("ARM_INDEX", "external_hound", "7200.0", "2400.0")
    hits: list[str] = []
    for path in SRC_EVAL.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                hits.append(f"{path.name}:{token}")
        if "12.0 +" in text or "12.0+" in text:
            hits.append(f"{path.name}:12.0+")
    assert hits == []


def test_manifest_records_failures_and_nulls(tmp_path: Path) -> None:
    target = _target("minivault-reentrancy", "reentrancy", 9.0)
    sheet = _prereg(targets=[target.target_id], session_usd=150.0)
    preregister(sheet, results_root=tmp_path, recorded_at="2026-08-23T00:00:00Z")
    crashed = ArmTranscript(
        events=[],
        usage=ArmUsage(),
        started_at="2026-08-23T00:00:00Z",
        ended_at="2026-08-23T00:00:01Z",
        exit_status="crash",
    )
    transport = ScriptedArmTransport(
        scripts={
            "A0:minivault-reentrancy": crashed,
            "A5:minivault-reentrancy": crashed,
        }
    )
    manifest = run_live_session(
        preregistration=sheet,
        transport=transport,
        targets=[target],
        cards=[],
        results_root=tmp_path,
        created_at="2026-08-23T00:01:00Z",
        seeds=(7,),
    )
    assert manifest.failures_included is True
    assert any(run.exit_status == "crash" for run in manifest.arms)
    assert manifest.null_metric_disclosures
    assert any("crash" in run.failures for run in manifest.arms)


def test_example_target_manifests_load() -> None:
    from ayran.evaluation.targets import load_target_dir

    loaded = load_target_dir(FIXTURES)
    ids = {item.target_id for item in loaded}
    assert "minivault-reentrancy" in ids
    assert "sharepool-inflation" in ids
    assert all(item.held_out for item in loaded)
