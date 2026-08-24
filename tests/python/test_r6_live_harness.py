"""R6 live evaluation harness: preregistration, contamination, caps, pause, honest scoring."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from ayran.evaluation.arms import arm_spec
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
from ayran.evaluation.transport import (
    ArmSpec,
    ArmTranscript,
    ArmUsage,
    LivePrimeTransport,
    ScriptedArmTransport,
)
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
        def run(self, arm, target, budget, **kwargs):  # type: ignore[no-untyped-def]
            result = super().run(arm, target, budget, **kwargs)
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


def test_stock_and_ayran_profiles_differ(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[dict[str, object]] = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.append({"argv": list(argv), "env": kwargs.get("env")})
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("ayran.evaluation.transport.subprocess.run", fake_run)

    task = "identical-question-for-both-arms"
    target = _target("minivault-reentrancy", "reentrancy", 9.0)
    socket = str(tmp_path / "ayran.sock")
    token = str(tmp_path / "token")
    transport = LivePrimeTransport(
        configured=True,
        prime_bin="prime",
        ayran_socket_path=socket,
        ayran_token_file=token,
    )
    transport.run(
        ArmSpec(arm="A0", capabilities=list(arm_spec("A0").capabilities)),
        target,
        {},
        task_text=task,
    )
    transport.run(
        ArmSpec(arm="A5", capabilities=list(arm_spec("A5").capabilities)),
        target,
        {},
        task_text=task,
    )
    assert len(captured) == 2
    stock_argv = captured[0]["argv"]
    ayran_argv = captured[1]["argv"]
    assert isinstance(stock_argv, list)
    assert isinstance(ayran_argv, list)
    assert task in stock_argv
    assert task in ayran_argv
    assert stock_argv[-1] == ayran_argv[-1] == task
    assert "--print" in stock_argv
    assert "--ayran" not in stock_argv
    stock_env = captured[0]["env"]
    assert stock_env is None or (
        isinstance(stock_env, dict)
        and "AYRAN_SOCKET_PATH" not in stock_env
        and "AYRAN_TOKEN_FILE" not in stock_env
    )
    assert "--ayran" in ayran_argv
    assert "--print" in ayran_argv
    ayran_env = captured[1]["env"]
    assert isinstance(ayran_env, dict)
    assert ayran_env.get("AYRAN_SOCKET_PATH") == socket
    assert ayran_env.get("AYRAN_TOKEN_FILE") == token


def test_timeout_yields_partial_transcript(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    partial = "partial stdout before kill"

    def boom(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(
            cmd=["prime"],
            timeout=0.01,
            output=partial,
            stderr="err-partial",
        )

    monkeypatch.setattr("ayran.evaluation.transport.subprocess.run", boom)

    target = _target("minivault-reentrancy", "reentrancy", 9.0)
    sheet = _prereg(targets=[target.target_id], session_usd=150.0)
    preregister(sheet, results_root=tmp_path, recorded_at="2026-08-23T00:00:00Z")
    live = LivePrimeTransport(configured=True, prime_bin="prime", timeout_s=0.01)
    manifest = run_live_session(
        preregistration=sheet,
        transport=live,
        targets=[target],
        cards=[],
        results_root=tmp_path,
        created_at="2026-08-23T00:01:00Z",
        seeds=(7,),
    )
    assert any(run.exit_status == "timeout" for run in manifest.arms)
    assert any("timeout" in run.failures for run in manifest.arms)
    transcripts = list(tmp_path.rglob("transcript.json"))
    assert transcripts
    body = json.loads(transcripts[0].read_text(encoding="utf-8"))
    assert body["exit_status"] == "timeout"
    assert partial in body["stdout"]
    assert body["ended_at"]


def test_service_run_live_feeds_ingested_cards_to_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T16 (live-corpus repair, 2026-08-24): service.run_live must feed the
    contamination gate the REAL staged incident inventory - an empty card
    list made the bar vacuous exactly once real incidents existed."""
    from types import SimpleNamespace

    from ayran.evaluation import service as eval_service
    from m7_fixtures import copy_knowledge

    knowledge_root = copy_knowledge(tmp_path)
    registry = knowledge_root / "registry" / "defihacklabs.yaml"
    registry.write_text(
        "\n".join(
            [
                "source_id: defihacklabs",
                "display_name: DeFiHackLabs exploit PoCs",
                "source_type: repository",
                'origin: "https://github.com/SunWeb3Sec/DeFiHackLabs"',
                "pin:",
                '  commit: "' + "3" * 40 + '"',
                '  archive_sha256: "sha256:' + "4" * 64 + '"',
                "license:",
                "  spdx_id: Apache-2.0",
                "  attribution_required: true",
                "  local_use: true",
                "  redistribution: true",
                "trust_tier: curated_external",
                "phase: ingested",
                "authors: [SunWeb3Sec]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    staging = knowledge_root / "staging" / "defihacklabs"
    staging.mkdir(parents=True)
    colliding = _incident("krec_collision", "minivault", "minivault")
    (staging / "records.json").write_text(
        json.dumps(
            {
                "source_id": "defihacklabs",
                "tree_hash": "sha256:" + "5" * 64,
                "taxonomy_version": "1.0.0",
                "conflicts": [],
                "records": [colliding.model_dump(mode="json")],
                "created_at": "2026-08-24T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    sheet_path = tmp_path / "prereg.json"
    sheet_path.write_text(
        json.dumps(_prereg(targets=["eval-minivault"]).model_dump(mode="json")),
        encoding="utf-8",
    )

    called = {"session": 0}

    def _refuse_session(**kwargs):  # pragma: no cover - must never run
        called["session"] += 1
        raise AssertionError("run_live_session must not launch on collision")

    monkeypatch.setattr("ayran.evaluation.live_runner.run_live_session", _refuse_session)
    with pytest.raises(ContaminationViolation):
        eval_service.run_live(
            preregistration=sheet_path,
            targets=FIXTURES,
            results_root=tmp_path / "results-collision",
            knowledge_root=knowledge_root,
        )
    assert called["session"] == 0

    # Non-colliding inventory passes the gate and reaches the session intact.
    benign = _incident("krec_benign", "totallyunrelatedprotocol", "otherincident")
    (staging / "records.json").write_text(
        json.dumps(
            {
                "source_id": "defihacklabs",
                "tree_hash": "sha256:" + "6" * 64,
                "taxonomy_version": "1.0.0",
                "conflicts": [],
                "records": [benign.model_dump(mode="json")],
                "created_at": "2026-08-24T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    def _fake_session(**kwargs):
        captured["cards"] = kwargs["cards"]
        return SimpleNamespace(model_dump=lambda mode="json": {"ok": True})

    captured: dict[str, object] = {}
    monkeypatch.setattr("ayran.evaluation.live_runner.run_live_session", _fake_session)
    payload = eval_service.run_live(
        preregistration=sheet_path,
        targets=FIXTURES,
        results_root=tmp_path / "results-clean",
        knowledge_root=knowledge_root,
    )
    assert payload == {"ok": True}
    cards = captured["cards"]
    assert [card.record_id for card in cards] == ["krec_benign"]
