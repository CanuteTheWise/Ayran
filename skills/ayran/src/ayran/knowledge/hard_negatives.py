"""Hard-negative knowledge records: first-class false-positive traps."""

from __future__ import annotations

from datetime import UTC, datetime

from ayran.context.ids import content_id
from ayran.knowledge.models import KnowledgeRecord
from ayran.knowledge.paths import PARSER_VERSION, PINNED_TIME

_SAFE_REENTRANCY = (
    "function withdraw(uint256 amount) public { "
    "uint256 bal = balances[msg.sender]; "
    "require(bal >= amount); "
    "balances[msg.sender] = 0; "
    "(bool ok,) = msg.sender.call{value: amount}(\"\"); "
    "require(ok); }"
)

_TEMPLATES: dict[str, tuple[str, str, str]] = {
    "reentrancy": (
        _SAFE_REENTRANCY,
        "Effects update balances to zero before the external call, so a callback cannot drain twice.",
        "The dangerous variant performs the external call before zeroing balances.",
    ),
    "oracle-manipulation": (
        "uint256 price = aggregator.latestRoundData().answer; "
        "require(answeredInRound >= roundId); require(updatedAt + stalePeriod >= block.timestamp);",
        "Staleness and round completeness checks reject a single-block spot price.",
        "The dangerous variant reads a raw spot or pair reserve without a freshness bound.",
    ),
    "access-control": (
        "function setOwner(address next) external onlyOwner { owner = next; }",
        "The privileged writer is gated by onlyOwner; an unprivileged caller cannot rotate control.",
        "The dangerous variant omits the modifier or uses tx.origin.",
    ),
    "arithmetic-overflow": (
        "unchecked { uint256 next = used + amount; require(next >= used); used = next; }",
        "The addition is checked for wrap even inside an unchecked block.",
        "The dangerous variant relies on implicit wrap of an accumulator.",
    ),
    "storage-collision": (
        "bytes32 constant SLOT = keccak256(\"ayran.example.owner\");",
        "A namespaced storage slot cannot collide with sequential inherited layout.",
        "The dangerous variant appends a new inherited state variable before an existing gap.",
    ),
}


def _stamp(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)


def generate_hard_negative(record: KnowledgeRecord) -> KnowledgeRecord:
    key = (record.mechanism or record.canonical_key or record.title).lower().replace(" ", "-")
    template_key = "reentrancy"
    for candidate in _TEMPLATES:
        if candidate in key:
            template_key = candidate
            break
    code, why_safe, distinction = _TEMPLATES[template_key]
    record_id = content_id("krec", "hardneg", record.record_id, template_key)
    return KnowledgeRecord(
        record_id=record_id,
        record_type="false_positive_trap",
        source_ref=record.source_ref,
        authors=list(record.authors),
        urls=list(record.urls),
        commit_or_version=record.commit_or_version,
        date=_stamp(PINNED_TIME),
        raw_hash=record.raw_hash,
        parser_version=PARSER_VERSION,
        license_info=record.license_info,
        title=f"Hard negative for {record.title or record.record_id}",
        summary=why_safe,
        language=record.language or "solidity",
        chain=record.chain,
        framework=record.framework,
        protocol=record.protocol,
        component=record.component,
        mechanism=record.mechanism,
        applicability_predicates=list(record.applicability_predicates),
        false_positive_conditions=[distinction],
        trust_tier=record.trust_tier,
        completeness=0.7,
        reproduction_status="not_applicable",
        safe_for_retrieval=True,
        safe_for_execution=False,
        hard_negative=True,
        why_safe=why_safe,
        distinction=distinction,
        safe_variant_code=code,
        canonical_key=f"hardneg-{record.canonical_key or record.record_id}",
        taxonomy=list(record.taxonomy),
    )


def ensure_hard_negatives(records: list[KnowledgeRecord]) -> list[KnowledgeRecord]:
    existing_traps = {
        item.canonical_key for item in records if item.hard_negative or item.record_type == "false_positive_trap"
    }
    extras: list[KnowledgeRecord] = []
    for record in records:
        if record.record_type != "mechanism":
            continue
        if record.hard_negatives:
            continue
        generated = generate_hard_negative(record)
        if generated.canonical_key in existing_traps:
            continue
        extras.append(generated)
        existing_traps.add(generated.canonical_key)
    updated: list[KnowledgeRecord] = []
    extra_ids = [item.record_id for item in extras]
    for record in records:
        if record.record_type == "mechanism" and extra_ids:
            linked = [
                item.record_id
                for item in extras
                if item.source_ref.locator == record.source_ref.locator
                or (record.mechanism and record.mechanism == item.mechanism)
            ]
            if linked:
                updated.append(
                    record.model_copy(update={"hard_negatives": sorted(set(record.hard_negatives + linked))})
                )
                continue
        updated.append(record)
    return updated + extras
