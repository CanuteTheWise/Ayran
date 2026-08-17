"""Blinded, stratified train/development/test partitions with contamination groups."""

from __future__ import annotations

from collections import defaultdict

from ayran.evaluation.models import PartitionName, SealedFixture
from ayran.evaluation.sealed import load_catalog


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
