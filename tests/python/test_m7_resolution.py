"""M7 entity resolution, conflicts, and hard negatives."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from ayran.knowledge.conflicts import detect_conflicts
from ayran.knowledge.corpus import build_release, query_corpus
from ayran.knowledge.entity_resolution import (
    VARIANT_OF,
    apply_resolution,
    exact_hash_key,
    resolve_against,
)
from ayran.knowledge.hard_negatives import generate_hard_negative
from ayran.knowledge.ingestion import ingest_source, load_staged_records
from ayran.knowledge.models import KnowledgeRecord, LicenseInfo, SourceRef
from m7_fixtures import copy_knowledge

LICENSE = LicenseInfo(spdx_id="MIT")
WHEN = datetime(2026, 8, 14, tzinfo=UTC)


def _record(**overrides: object) -> KnowledgeRecord:
    payload = {
        "record_id": "krec_00000000000000000000000001",
        "record_type": "incident",
        "source_ref": SourceRef(source_id="solodit", locator="a.yaml", commit_or_version="1"),
        "commit_or_version": "1",
        "date": WHEN,
        "raw_hash": "sha256:" + "a" * 64,
        "parser_version": "1.0.0",
        "license_info": LICENSE,
        "title": "The DAO reentrancy 2016",
        "root_cause": "external-call-before-balance-update",
        "mechanism": "reentrancy",
        "impact": "3.6 million ETH",
        "fix": "CEI",
    }
    payload.update(overrides)
    return KnowledgeRecord.model_validate(payload)


def test_exact_hash_and_variant_link() -> None:
    primary = _record()
    duplicate = _record(
        record_id="krec_00000000000000000000000002",
        source_ref=SourceRef(source_id="other", locator="b.yaml", commit_or_version="1"),
    )
    assert exact_hash_key(primary) == exact_hash_key(duplicate)
    resolution = resolve_against(duplicate, [primary])
    assert resolution.relation == VARIANT_OF
    assert resolution.primary_id == primary.record_id
    linked = apply_resolution(duplicate, resolution)
    assert linked.variant_of == primary.record_id
    assert primary.record_id in linked.near_duplicate_lineage


def test_root_cause_fingerprint_and_conflicts() -> None:
    left = _record()
    right = _record(
        record_id="krec_00000000000000000000000003",
        source_ref=SourceRef(source_id="alt", locator="c.yaml"),
        raw_hash="sha256:" + "b" * 64,
        impact="50 million USD",
        fix="hard fork",
    )
    groups = detect_conflicts([left, right])
    kinds = {item.kind for item in groups}
    assert "loss_amount" in kinds or "fix" in kinds
    assert all(item.reviewer_disposition == "unresolved" for item in groups)


def test_hard_negative_distinguishes_safe_variant() -> None:
    mechanism = _record(
        record_id="krec_00000000000000000000000004",
        record_type="mechanism",
        title="Classic reentrancy",
        mechanism="reentrancy",
        canonical_key="reentrancy",
    )
    trap = generate_hard_negative(mechanism)
    assert trap.hard_negative is True
    assert trap.record_type == "false_positive_trap"
    assert trap.safe_variant_code
    assert trap.why_safe
    assert "before" in (trap.distinction or "").lower() or "zero" in (trap.why_safe or "").lower()
    assert trap.safe_for_execution is False


def test_solodit_conflict_group_is_retained(tmp_path: Path) -> None:
    root = copy_knowledge(tmp_path)
    ingest_source(root, "solodit")
    records = load_staged_records(root, "solodit")
    dao = [item for item in records if "dao" in item.title.lower()]
    assert len(dao) >= 2
    groups = detect_conflicts(dao)
    assert groups
    build_release(root, version="v0.1.0-conflict")
    queried = query_corpus(root, record_type="incident")
    assert queried
    assert any(item.get("conflicts") or item.get("contradiction_group") for item in queried)
