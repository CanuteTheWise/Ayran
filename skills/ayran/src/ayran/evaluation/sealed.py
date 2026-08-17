"""Sealed evaluation fixtures: opaque IDs, hashes, and physical isolation from ingestion."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ayran.evaluation.models import GroundTruth, PartitionName, SealedFixture
from ayran.evaluation.paths import sealed_catalog_path
from ayran.graph.canonical import canonical_hash

_SEALED_DOMAIN = "ayran.evaluation.sealed.v1"


def opaque_id(key: str) -> str:
    digest = hashlib.sha256(f"{_SEALED_DOMAIN}:{key}".encode()).hexdigest()
    return "sev_" + digest[:24]


def _fixture(
    key: str,
    *,
    project_family: str,
    root_cause_family: str,
    contamination_group: str,
    partition: PartitionName,
    scenario: str,
    ground_truth: list[GroundTruth],
    first_arm: str = "A5",
    optional_tool: str = "",
    required_tool: str = "",
    flaky: bool = False,
    resume: bool = False,
) -> SealedFixture:
    unsigned = {
        "key": key,
        "project_family": project_family,
        "root_cause_family": root_cause_family,
        "contamination_group": contamination_group,
        "partition": partition,
        "scenario": scenario,
        "ground_truth": [item.model_dump(mode="json") for item in ground_truth],
        "first_arm": first_arm,
        "optional_tool": optional_tool,
        "required_tool": required_tool,
        "flaky": flaky,
        "resume": resume,
    }
    return SealedFixture(
        fixture_id=opaque_id(key),
        content_hash=canonical_hash(unsigned),
        project_family=project_family,
        root_cause_family=root_cause_family,
        contamination_group=contamination_group,
        partition=partition,
        scenario=scenario,
        ground_truth=ground_truth,
        first_arm=first_arm,  # type: ignore[arg-type]
        optional_tool=optional_tool,
        required_tool=required_tool,
        flaky=flaky,
        resume=resume,
    )


def built_in_catalog() -> list[SealedFixture]:
    """Nine §19.7 scenarios, stratified and grouped against contamination."""

    reentrancy = GroundTruth(
        root_cause_id="rc_cei_external_call",
        root_cause_family="reentrancy",
        severity=0.9,
        novel=True,
    )
    rounding = GroundTruth(
        root_cause_id="rc_share_rounding",
        root_cause_family="accounting",
        severity=0.6,
        novel=True,
    )
    return [
        _fixture(
            "s1",
            project_family="fam_vault",
            root_cause_family="none",
            contamination_group="grp_clean",
            partition="train",
            scenario="clean_target",
            ground_truth=[],
            first_arm="A0",
        ),
        _fixture(
            "s2",
            project_family="fam_vault",
            root_cause_family="reentrancy",
            contamination_group="grp_cei",
            partition="test",
            scenario="known_vulnerable",
            ground_truth=[reentrancy],
            first_arm="A5",
        ),
        _fixture(
            "s3",
            project_family="fam_vault",
            root_cause_family="accounting",
            contamination_group="grp_shares",
            partition="development",
            scenario="ambiguous_economic",
            ground_truth=[rounding],
            first_arm="A3",
        ),
        _fixture(
            "s4",
            project_family="fam_bridge",
            root_cause_family="reentrancy",
            contamination_group="grp_cei",
            partition="test",
            scenario="duplicate_known",
            ground_truth=[
                GroundTruth(
                    root_cause_id="rc_cei_historical",
                    root_cause_family="reentrancy",
                    severity=0.7,
                    novel=False,
                )
            ],
            first_arm="A4",
        ),
        _fixture(
            "s5",
            project_family="fam_vault",
            root_cause_family="reentrancy",
            contamination_group="grp_cei",
            partition="development",
            scenario="flaky_poc",
            ground_truth=[reentrancy],
            first_arm="A5",
            flaky=True,
        ),
        _fixture(
            "s6",
            project_family="fam_amm",
            root_cause_family="oracle",
            contamination_group="grp_oracle",
            partition="train",
            scenario="unavailable_optional_tool",
            ground_truth=[],
            first_arm="A2",
            optional_tool="adapter.slither",
        ),
        _fixture(
            "s7",
            project_family="fam_vault",
            root_cause_family="none",
            contamination_group="grp_tools",
            partition="development",
            scenario="required_tool_failure",
            ground_truth=[],
            first_arm="A2",
            required_tool="adapter.foundry",
        ),
        _fixture(
            "s8",
            project_family="fam_vault",
            root_cause_family="reentrancy",
            contamination_group="grp_cei",
            partition="test",
            scenario="resume_after_crash",
            ground_truth=[reentrancy],
            first_arm="A5",
            resume=True,
        ),
        _fixture(
            "s9",
            project_family="fam_nft",
            root_cause_family="none",
            contamination_group="grp_clean",
            partition="test",
            scenario="no_finding_report",
            ground_truth=[],
            first_arm="A0",
        ),
    ]


def load_catalog(evals: Path | str | None = None) -> list[SealedFixture]:
    path = sealed_catalog_path(Path(evals) if evals else None)
    if path.is_file():
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload.get("fixtures") if isinstance(payload, dict) else payload
        if isinstance(items, list) and items:
            return [SealedFixture.model_validate(item) for item in items if isinstance(item, dict)]
    return built_in_catalog()


def dump_catalog(destination: Path) -> dict[str, Any]:
    fixtures = built_in_catalog()
    payload = {
        "schema_version": "1.0.0",
        "kind": "ayran-sealed-evaluation-catalog",
        "ingestion": "forbidden",
        "fixtures": [item.model_dump(mode="json") for item in fixtures],
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def fixture_by_id(fixture_id: str, evals: Path | str | None = None) -> SealedFixture | None:
    for item in load_catalog(evals):
        if item.fixture_id == fixture_id:
            return item
    return None


def all_sealed_tokens(evals: Path | str | None = None) -> set[str]:
    tokens: set[str] = set()
    for item in load_catalog(evals):
        tokens.add(item.fixture_id)
        tokens.add(item.content_hash)
        tokens.add(item.content_hash.removeprefix("sha256:"))
        for truth in item.ground_truth:
            tokens.add(truth.root_cause_id)
    return tokens
