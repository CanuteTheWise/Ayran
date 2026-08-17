"""Bounded ContextPack compiler. Labels are load-bearing; assumptions stay assumptions."""

from __future__ import annotations

import json
import re
from typing import Any

from ayran.api.validators import validate_contract
from ayran.context.contracts import default_target_identity, provenance_record
from ayran.context.ids import DEFAULT_RUN_ID, ZERO_HASH, content_id
from ayran.context.labels import Classification
from ayran.context.serialize import estimate_section_tokens, serialize_injection
from ayran.context.view import GraphView, reconstruction_fingerprint
from ayran.graph.canonical import object_hash, utc_now

RECONSTRUCTION_TITLES = (
    "Active hypothesis",
    "Result so far",
    "Next action",
    "Dead approaches",
    "Untried dimensions",
)

ACTIVE_STATUSES = {
    "lead",
    "supported",
    "poc_worthy",
    "observed",
    "defect_pinned",
    "needs_missing_fact",
    "needs_reformulation",
}
DEAD_STATUSES = {"falsified", "parked", "duplicate_known_issue"}
_RUN_ID_OK = re.compile(r"^run_[0-9A-HJKMNP-TV-Z]{26}$")


def _clip(text: str, limit: int = 1200) -> str:
    stripped = " ".join(text.split())
    if not stripped:
        return "none recorded"
    if len(stripped) <= limit:
        return stripped
    return stripped[: limit - 1] + "…"


def _section(
    classification: Classification,
    title: str,
    content: str,
    source_ids: list[str],
) -> dict[str, Any]:
    unique_ids = sorted({item for item in source_ids if item})[:256]
    return {
        "classification": classification,
        "title": title[:256],
        "content": _clip(content, 16000),
        "source_ids": unique_ids,
    }


def _canonical_run_id(run_id: str, fallback: str) -> str:
    if _RUN_ID_OK.fullmatch(run_id):
        return run_id
    if _RUN_ID_OK.fullmatch(fallback):
        return fallback
    return DEFAULT_RUN_ID


def _claims(items: list[dict[str, Any]], empty: str, *, field: str = "claim") -> tuple[str, list[str]]:
    if not items:
        return empty, []
    lines: list[str] = []
    ids: list[str] = []
    for item in sorted(items, key=lambda row: str(row.get("hypothesis_id") or row.get("id") or ""))[:12]:
        claim = str(item.get(field) or item.get("status") or "unspecified")
        origin = str(item.get("origin") or "unknown")
        status = str(item.get("status") or "unknown")
        identifier = str(item.get("hypothesis_id") or item.get("id") or "")
        lines.append(f"{status}/{origin}: {claim}")
        if identifier:
            ids.append(identifier)
    return "; ".join(lines), ids


def _trim_to_budget(
    sections: list[dict[str, Any]],
    token_budget: int,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    omitted = {"target": 0, "global": 0, "learning": 0}
    protected = {title.lower() for title in RECONSTRUCTION_TITLES}

    def tokens() -> int:
        return sum(estimate_section_tokens(item["title"], item["content"]) for item in sections)

    while tokens() > token_budget and len(sections) > 6:
        drop_at = None
        for index in range(len(sections) - 1, -1, -1):
            title = str(sections[index]["title"])
            if title.lower() not in protected and title not in {"Scope"}:
                drop_at = index
                break
        if drop_at is None:
            drop_at = len(sections) - 1
        dropped = sections.pop(drop_at)
        if dropped["classification"] == "HISTORICAL_REFERENCE":
            omitted["global"] += 1
        else:
            omitted["target"] += 1
    return sections, omitted


def compile_from_view(
    view: GraphView,
    *,
    token_budget: int | None = None,
    purpose: str | None = None,
    role: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Assemble one contract-valid ContextPack from a GraphView."""

    budget = max(256, min(int(token_budget or view.token_budget), 1000000))
    created = created_at or view.created_at or utc_now()
    identity = view.target_identity or default_target_identity()
    run_id = _canonical_run_id(view.run_id, DEFAULT_RUN_ID)
    policy = view.knowledge_policy if view.knowledge_policy in {
        "target_only",
        "knowledge_blind",
        "graph_aware",
    } else "target_only"

    hypotheses = list(view.hypotheses)
    active = [item for item in hypotheses if item.get("status") in ACTIVE_STATUSES]
    leads = [item for item in hypotheses if item.get("status") == "lead"]
    dead = [item for item in hypotheses if item.get("status") in DEAD_STATUSES]
    questions = [
        item for item in hypotheses if item.get("status") in {"needs_missing_fact", "needs_reformulation"}
    ]
    questions.extend(view.open_questions)

    active_text, active_ids = _claims(active, "none recorded")
    lead_text, lead_ids = _claims(leads, "none recorded")
    dead_text, dead_ids = _claims(dead, "none recorded")
    if view.dead_ends:
        extra = "; ".join(
            f"{item.get('approach', 'approach')}: {item.get('reason', 'rejected')}"
            for item in sorted(view.dead_ends, key=lambda row: str(row.get("approach") or ""))[:8]
        )
        dead_text = extra if dead_text == "none recorded" else f"{dead_text}; {extra}"
    if view.contradictions:
        conflict_text = "; ".join(
            f"{item.get('kind', 'conflict')}:{item.get('left')}/{item.get('right')}"
            for item in sorted(view.contradictions, key=lambda row: str(row.get("id") or ""))[:8]
        )
        dead_text = (
            conflict_text if dead_text == "none recorded" else f"{dead_text}; {conflict_text}"
        )
    question_text, question_ids = _claims(questions, "none recorded", field="question")
    if question_text == "none recorded" and view.open_questions:
        question_text, question_ids = _claims(
            [{"claim": item.get("question"), "hypothesis_id": item.get("id")} for item in view.open_questions],
            "none recorded",
        )

    evidence_lines = [
        str(item.get("evidence_grade") or "lead")
        for item in sorted(view.evidence, key=lambda row: str(row.get("evidence_id") or ""))[:8]
    ]
    evidence_ids = [
        str(item.get("evidence_id"))
        for item in view.evidence
        if item.get("evidence_id")
    ][:256]
    evidence_text = ", ".join(evidence_lines) if evidence_lines else "none recorded"

    cells_examined = 0
    cells_remaining = 0
    cells_blocked = 0
    coverage_bits: list[str] = []
    coverage_ids: list[str] = []
    for cell in sorted(view.coverage_cells, key=lambda row: str(row.get("coverage_cell_id") or "")):
        identifier = str(cell.get("coverage_cell_id") or "")
        dimension = str(cell.get("dimension") or "unspecified")
        status = str(cell.get("status") or "open")
        if status in {"examined", "accepted_residual_risk"}:
            cells_examined += 1
        elif status == "blocked":
            cells_blocked += 1
            coverage_bits.append(f"{dimension}=blocked")
        else:
            cells_remaining += 1
            coverage_bits.append(f"{dimension}={status}")
        if identifier:
            coverage_ids.append(identifier)
    untried = "; ".join(coverage_bits) if coverage_bits else question_text
    coverage_summary = (
        f"examined={cells_examined}; remaining_risk_weighted={cells_remaining}; "
        f"blocked={cells_blocked}"
    )

    fact_lines: list[str] = []
    fact_ids: list[str] = []
    for unit in sorted(view.source_units, key=lambda row: str(row.get("name") or ""))[:16]:
        kind = str(unit.get("kind") or "source")
        name = str(unit.get("name") or "unnamed")
        span = str(unit.get("span") or unit.get("locator") or "")
        fact_lines.append(f"{kind}:{name} {span}".strip())
        if unit.get("id"):
            fact_ids.append(str(unit["id"]))
    for node in sorted(view.nodes, key=lambda row: str(row.get("node_id") or ""))[:16]:
        if node.get("node_type") in {"Function", "StateVariable", "Contract"}:
            fact_lines.append(f"{node.get('node_type')}:{node.get('node_id')}")
            fact_ids.append(str(node["node_id"]))
    facts_text = "; ".join(fact_lines) if fact_lines else "none recorded"

    assumption_lines = [
        str(item.get("claim") or item.get("description") or "")
        for item in hypotheses
        if item.get("trust_class") == "model_assumption"
    ]
    assumptions_text = "; ".join(item for item in assumption_lines if item) or "none recorded"

    budget_state = view.budget_state or {}
    audit_context = (
        f"run={run_id}; cluster={view.cluster_id}; phase={view.phase}; "
        f"cursor={view.cursor}; knowledge_policy={policy}; "
        f"budget={json.dumps(budget_state, sort_keys=True, separators=(',', ':')) if budget_state else 'unset'}"
    )

    next_action = "continue mapping, hypothesizing, and gathering target evidence within scope"
    if leads:
        next_action = "triage unverified leads and gather executable evidence"
    elif active:
        next_action = "advance the active hypothesis through the evidence ladder"
    elif coverage_bits:
        next_action = "cover untried dimensions before declaring residual risk"
    if view.manual_next:
        next_action = "manual_next: wait for operator or model input"

    roots = [item or "." for item in view.included_roots]
    root_text = ", ".join(roots) if roots else "none bound"
    policy_content = (
        f"In-scope paths: {root_text}. The sidecar denies mapped tools outside those "
        "paths; do not retry denials. Leads are not findings. Do not call an untested "
        "surface safe."
    )
    if view.policy_constraints:
        policy_content = policy_content + " " + "; ".join(view.policy_constraints[:4])

    retrieved_lines: list[str] = []
    retrieved_ids: list[str] = []
    if policy == "graph_aware":
        for card in sorted(
            view.global_mechanisms + view.global_incidents + view.global_patterns,
            key=lambda row: str(row.get("id") or row.get("title") or ""),
        )[:8]:
            retrieved_lines.append(str(card.get("title") or card.get("name") or "reference"))
            if card.get("id"):
                retrieved_ids.append(str(card["id"]))
    retrieved_text = "; ".join(retrieved_lines) if retrieved_lines else ""

    sections: list[dict[str, Any]] = [
        _section("POLICY", "Scope", policy_content, [view.scope_id] if view.scope_id else []),
        _section("DETERMINISTIC_FACT", "Audit context", audit_context, []),
        _section("HYPOTHESIS", "Active hypothesis", active_text, active_ids),
        _section("HYPOTHESIS", "Active hypotheses", active_text, active_ids),
        _section("RUNTIME_OBSERVATION", "Result so far", evidence_text, evidence_ids),
        _section("DETERMINISTIC_FACT", "Next action", next_action, []),
        _section("COUNTEREVIDENCE", "Dead approaches", dead_text, dead_ids),
        _section("COUNTEREVIDENCE", "Dead ends", dead_text, dead_ids),
        _section("ASSUMPTION", "Untried dimensions", untried, coverage_ids or question_ids),
        _section("DETERMINISTIC_FACT", "Coverage summary", coverage_summary, coverage_ids),
        _section("DETERMINISTIC_FACT", "Known facts", facts_text, fact_ids),
        _section("ASSUMPTION", "Assumptions", assumptions_text, []),
        _section("ASSUMPTION", "Open questions", question_text, question_ids),
        _section("HYPOTHESIS", "Unverified leads", lead_text, lead_ids),
    ]
    if retrieved_text and policy == "graph_aware":
        sections.append(
            _section("HISTORICAL_REFERENCE", "Retrieved context", retrieved_text, retrieved_ids)
        )
    elif policy != "graph_aware":
        # Explicitly absent: historical references are not facts.
        pass

    sections, omitted = _trim_to_budget(sections, budget)
    included_object_ids = sorted({item for section in sections for item in section["source_ids"]})
    pack_id = content_id(
        "ctx",
        run_id,
        view.cluster_id,
        str(view.cursor),
        purpose or view.purpose,
        role or view.role,
        view.snapshot_hash(),
    )
    query_id = content_id("qry", pack_id, "compile")
    based_on = view.event_hash if str(view.event_hash).startswith("sha256:") else ZERO_HASH
    policy_hash = view.policy_checksum if str(view.policy_checksum).startswith("sha256:") else ZERO_HASH
    config_hash = view.config_checksum if str(view.config_checksum).startswith("sha256:") else ZERO_HASH
    pack: dict[str, Any] = {
        "schema_version": "1.0.0",
        "context_pack_id": pack_id,
        "created_at": created,
        "run_id": run_id,
        "target_identity": identity,
        "purpose": (purpose or view.purpose)[:256],
        "role": (role or view.role)[:128],
        "graph_cursor": int(view.cursor),
        "query_ids": [query_id],
        "included_object_ids": included_object_ids,
        "included_evidence_ids": evidence_ids[:256],
        "excluded_object_ids": [],
        "omitted_counts": omitted,
        "token_estimate": 0,
        "policy_checksum": policy_hash,
        "config_checksum": config_hash,
        "based_on_event_hash": based_on,
        "fresh_until_event": None,
        "knowledge_policy": policy,
        "sections": sections,
        "provenance": [provenance_record(created_at=created, raw_hash=based_on, material=pack_id)],
        "integrity": {
            "algorithm": "sha256",
            "canonicalization": "rfc8785",
            "content_hash": ZERO_HASH,
            "excluded_fields": ["integrity.content_hash"],
        },
    }
    pack["token_estimate"] = sum(
        estimate_section_tokens(section["title"], section["content"]) for section in sections
    )
    pack["integrity"]["content_hash"] = object_hash(pack)
    validate_contract("context-pack", pack)
    return pack


def compile_context_pack(
    store: Any,
    *,
    run_id: str,
    token_budget: int = 4000,
    purpose: str = "audit-turn",
    role: str = "root-auditor",
    policy_checksum: str | None = None,
    config_checksum: str | None = None,
    degraded_note: str | None = None,
    cluster_id: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """M3-compatible entry: snapshot the live projection, then compile."""

    from ayran.context.queries import OntologyQueries, snapshot_view

    queries = OntologyQueries(store=store)
    view = snapshot_view(queries, cluster_id=cluster_id, run_id=run_id)
    view.token_budget = token_budget
    view.purpose = purpose
    view.role = role
    if policy_checksum:
        view.policy_checksum = policy_checksum
    if config_checksum:
        view.config_checksum = config_checksum
    if degraded_note:
        view.policy_constraints = [degraded_note, *view.policy_constraints]
    return compile_from_view(
        view,
        token_budget=token_budget,
        purpose=purpose,
        role=role,
        created_at=created_at,
    )


def compile_with_injection(
    view: GraphView,
    **kwargs: Any,
) -> dict[str, Any]:
    pack = compile_from_view(view, **kwargs)
    return {
        "pack": pack,
        "injection_text": serialize_injection(pack),
        "reconstruction": reconstruction_fingerprint(view),
        "reconstruction_ok": True,
        "content_hash": pack["integrity"]["content_hash"],
    }
