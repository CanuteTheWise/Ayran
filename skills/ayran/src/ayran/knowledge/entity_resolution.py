"""Entity resolution for Global records (blueprint §7.4). No majority vote."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ayran.context.ids import content_id
from ayran.knowledge.models import KnowledgeRecord

LEARNED_FROM = "LEARNED_FROM"
VARIANT_OF = "VARIANT_OF"


@dataclass(frozen=True, slots=True)
class Resolution:
    record_id: str
    relation: str | None
    primary_id: str | None
    reason: str


def exact_hash_key(record: KnowledgeRecord) -> str:
    return record.raw_hash


def canonical_locator_key(record: KnowledgeRecord) -> str:
    ref = record.source_ref
    return "|".join(
        [
            ref.source_id,
            ref.commit_or_version or record.commit_or_version,
            ref.locator,
        ]
    )


def project_fork_key(record: KnowledgeRecord) -> str:
    lineage = record.near_duplicate_lineage[0] if record.near_duplicate_lineage else ""
    return lineage or "|".join(filter(None, [record.protocol, record.component, record.title.lower()]))


def root_cause_fingerprint(record: KnowledgeRecord) -> str:
    material = "|".join(
        [
            (record.root_cause or record.mechanism or "").lower(),
            (record.invariant or "").lower(),
            (record.component or "").lower(),
            " ".join(sorted(step.lower() for step in record.attack_steps[:4])),
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return digest[:32]


def semantic_key(record: KnowledgeRecord) -> str:
    tokens = " ".join(
        filter(
            None,
            [
                record.title.lower(),
                record.summary.lower(),
                record.mechanism,
                record.root_cause,
            ],
        )
    )
    return " ".join(sorted(set(tokens.split())))


def resolve_against(
    record: KnowledgeRecord, existing: list[KnowledgeRecord]
) -> Resolution:
    """Link variants; never erase or merge primaries."""

    for other in existing:
        if other.record_id == record.record_id:
            return Resolution(record.record_id, None, None, "self")
        if exact_hash_key(other) == exact_hash_key(record) and other.raw_hash:
            return Resolution(record.record_id, VARIANT_OF, other.record_id, "exact_hash")
        if canonical_locator_key(other) == canonical_locator_key(record) and record.source_ref.locator:
            return Resolution(record.record_id, VARIANT_OF, other.record_id, "canonical_source")
        if (
            project_fork_key(other)
            and project_fork_key(other) == project_fork_key(record)
            and other.record_type == record.record_type
            and other.title.lower() == record.title.lower()
        ):
            return Resolution(record.record_id, VARIANT_OF, other.record_id, "project_fork")
        if (
            record.record_type in {"incident", "mechanism", "finding_pattern"}
            and other.record_type == record.record_type
            and root_cause_fingerprint(other) == root_cause_fingerprint(record)
            and record.root_cause
        ):
            return Resolution(record.record_id, VARIANT_OF, other.record_id, "root_cause_fingerprint")
        if semantic_key(other) and semantic_key(other) == semantic_key(record) and other.source_ref.source_id != record.source_ref.source_id:
            return Resolution(record.record_id, LEARNED_FROM, other.record_id, "semantic_candidate")
    return Resolution(record.record_id, None, None, "primary")


def apply_resolution(record: KnowledgeRecord, resolution: Resolution) -> KnowledgeRecord:
    if resolution.relation == VARIANT_OF and resolution.primary_id:
        lineage = list(record.near_duplicate_lineage)
        if resolution.primary_id not in lineage:
            lineage.append(resolution.primary_id)
        return record.model_copy(update={"variant_of": resolution.primary_id, "near_duplicate_lineage": lineage})
    if resolution.relation == LEARNED_FROM and resolution.primary_id:
        return record.model_copy(update={"learned_from": resolution.primary_id})
    return record


def stable_group_id(*parts: str) -> str:
    return content_id("cgrp", *parts)
