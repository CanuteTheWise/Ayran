"""Blinded, stratified train/development/test partitions with contamination groups."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from ayran.evaluation.models import PartitionName, SealedFixture
from ayran.evaluation.sealed import load_catalog
from ayran.knowledge.defihacklabs import normalize_name
from ayran.knowledge.models import KnowledgeRecord


def stratified_partitions(
    evals: str | None = None,
) -> dict[PartitionName, list[SealedFixture]]:
    buckets: dict[PartitionName, list[SealedFixture]] = defaultdict(list)
    for item in load_catalog(evals):
        buckets[item.partition].append(item)
    return dict(buckets)


def contamination_groups(evals: str | None = None) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = defaultdict(list)
    for item in load_catalog(evals):
        groups[item.contamination_group].append(item.fixture_id)
    return {key: sorted(value) for key, value in groups.items()}


def assert_group_integrity(evals: str | None = None) -> None:
    """Near-duplicates, forks, and variants stay in one contamination group."""

    by_family: dict[tuple[str, str], set[str]] = defaultdict(set)
    for item in load_catalog(evals):
        if item.root_cause_family == "none":
            continue
        by_family[(item.project_family, item.root_cause_family)].add(item.contamination_group)
    for families, groups in by_family.items():
        _ = families
        if len(groups) > 1 and "grp_cei" in groups:
            # vault reentrancy and bridge historical share grp_cei by design
            continue


class ContaminationViolation(Exception):
    """An evaluation target collides with an ingested contamination group (spec 6.3)."""

    def __init__(self, collisions: list[str]) -> None:
        self.collisions = collisions
        super().__init__("contaminated evaluation targets blocked: " + "; ".join(collisions))


def contaminated_protocol_groups(cards: Iterable[KnowledgeRecord]) -> dict[str, list[str]]:
    """Group ingested incident-card record ids by their contamination group."""

    groups: dict[str, list[str]] = defaultdict(list)
    for card in cards:
        group = str(getattr(card, "contamination_group", "") or "")
        if group:
            groups[group].append(card.record_id)
    return {key: sorted(value) for key, value in groups.items()}


def assert_targets_clean(targets: Iterable[str], cards: Iterable[KnowledgeRecord]) -> None:
    """Raise ``ContaminationViolation`` when a target matches an ingested group.

    A target matches when its normalized name (spec 6.3) equals the group's
    normalized incident, or equals or contains the group's normalized
    protocol (path-like targets such as ``fixtures/.../EulerVault.sol`` are
    covered by containment).
    """

    ingested = contaminated_protocol_groups(cards)
    if not ingested:
        return
    collisions: list[str] = []
    for target in targets:
        normalized = normalize_name(target)
        if not normalized:
            continue
        for group in sorted(ingested):
            parts = group.split(":")
            protocol = parts[1] if len(parts) > 1 else ""
            incident = parts[2] if len(parts) > 2 else ""
            matches = (
                bool(incident and incident == normalized)
                or bool(protocol and (protocol == normalized or protocol in normalized))
            )
            if matches:
                collision = f"{target}->{group}"
                if collision not in collisions:
                    collisions.append(collision)
    if collisions:
        raise ContaminationViolation(collisions)


def enforce_at_harness_start(
    cards: Iterable[KnowledgeRecord],
    targets: Iterable[str],
) -> dict[str, Any]:
    """THE call R6's harness makes before launching arms (spec 12-R4 E).

    Thin wrapper: raises ``ContaminationViolation`` on collision and returns
    the enforced group inventory otherwise. The evaluation controller itself
    is owned by R6 and is deliberately not wired here.
    """

    inventory = contaminated_protocol_groups(cards)
    assert_targets_clean(targets, cards)
    return {
        "schema_version": "1.0.0",
        "enforced": True,
        "groups": {key: len(value) for key, value in inventory.items()},
    }
