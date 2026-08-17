"""Conflicting assertions: retain all sides; never majority-vote truth."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ayran.knowledge.entity_resolution import root_cause_fingerprint, stable_group_id
from ayran.knowledge.models import KnowledgeRecord

ConflictKind = Literal["loss_amount", "root_cause", "fix", "affected_version", "other"]


class ConflictGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    group_id: str
    kind: ConflictKind
    record_ids: list[str]
    trust_tiers: list[str]
    sources: list[str]
    reviewer_disposition: str = "unresolved"
    note: str = "conflicting assertions retained; no majority vote"


def _conflict_kind(left: KnowledgeRecord, right: KnowledgeRecord) -> ConflictKind | None:
    if left.impact and right.impact and left.impact != right.impact:
        return "loss_amount"
    if (left.root_cause or left.mechanism) and (right.root_cause or right.mechanism) and (
        (left.root_cause or left.mechanism) != (right.root_cause or right.mechanism)
    ):
        return "root_cause"
    if left.fix and right.fix and left.fix != right.fix:
        return "fix"
    if (
        left.commit_or_version
        and right.commit_or_version
        and left.commit_or_version != right.commit_or_version
        and left.title.lower() == right.title.lower()
    ):
        return "affected_version"
    return None


def detect_conflicts(records: list[KnowledgeRecord]) -> list[ConflictGroup]:
    groups: list[ConflictGroup] = []
    seen: set[tuple[str, str, str]] = set()
    for index, left in enumerate(records):
        for right in records[index + 1 :]:
            if left.record_id == right.record_id:
                continue
            same_subject = (
                left.title.lower() == right.title.lower()
                or (
                    left.record_type == right.record_type
                    and root_cause_fingerprint(left) == root_cause_fingerprint(right)
                    and bool(left.root_cause or left.mechanism)
                )
            )
            if not same_subject:
                continue
            kind = _conflict_kind(left, right)
            if kind is None:
                continue
            ordered = tuple(sorted((kind, left.record_id, right.record_id)))
            key = (ordered[0], ordered[1], ordered[2])
            if key in seen:
                continue
            seen.add(key)
            group_id = stable_group_id(kind, left.record_id, right.record_id)
            groups.append(
                ConflictGroup(
                    group_id=group_id,
                    kind=kind,
                    record_ids=sorted([left.record_id, right.record_id]),
                    trust_tiers=sorted({left.trust_tier, right.trust_tier}),
                    sources=sorted({left.source_ref.source_id, right.source_ref.source_id}),
                )
            )
    return sorted(groups, key=lambda item: item.group_id)


def attach_conflicts(records: list[KnowledgeRecord], groups: list[ConflictGroup]) -> list[KnowledgeRecord]:
    by_id = {item.group_id: item for item in groups}
    membership: dict[str, list[str]] = {}
    for group in by_id.values():
        for record_id in group.record_ids:
            membership.setdefault(record_id, []).append(group.group_id)
    updated: list[KnowledgeRecord] = []
    for record in records:
        group_ids = membership.get(record.record_id) or []
        if not group_ids:
            updated.append(record)
            continue
        updated.append(
            record.model_copy(
                update={
                    "conflicts": sorted(set(record.conflicts + group_ids)),
                    "contradiction_group": group_ids[0],
                }
            )
        )
    return updated


class ConflictIndex(BaseModel):
    model_config = ConfigDict(extra="forbid")
    groups: list[ConflictGroup] = Field(default_factory=list)
