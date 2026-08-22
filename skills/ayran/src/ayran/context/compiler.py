"""Bounded ContextPack compiler. Labels are load-bearing; assumptions stay assumptions."""

from __future__ import annotations

import json
import re
from typing import Any

from ayran.api.validators import validate_contract
from ayran.context.contracts import default_target_identity, provenance_record
from ayran.context.ids import DEFAULT_RUN_ID, ZERO_HASH, content_id
from ayran.context.labels import Classification
from ayran.context.lenses import (
    QUARANTINE_PLACEHOLDER,
    census_from_view,
    compile_lens_blocks,
    coupled_state_pairs,
    money_map_signaled,
    remaining_from_view,
)
from ayran.context.serialize import estimate_section_tokens, serialize_injection
from ayran.context.view import GraphView, reconstruction_fingerprint
from ayran.graph.canonical import object_hash, utc_now
from ayran.router.injection import looks_like_injection

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
_ID_OK = re.compile(r"^[a-z][a-z0-9]{1,11}_[0-9A-HJKMNP-TV-Z]{26}$")
MONEY_MAP_LINE_CAP = 200
QUARANTINE_MARK = "[QUARANTINED:"


class CompileError(ValueError):
    """Fail-closed context-pack compilation (INV-5.3 silent-drop, INV-5.8 census)."""


def _writer_identity(item: dict[str, Any]) -> str:
    writer = item.get("writer")
    if isinstance(writer, dict) and writer.get("kind") and writer.get("id"):
        return f"writer={writer.get('kind')}:{writer.get('id')}"
    history = item.get("transition_history") or []
    if history and isinstance(history[0], dict):
        actor = history[0].get("actor") or {}
        if actor.get("kind") and actor.get("id"):
            return f"writer={actor.get('kind')}:{actor.get('id')}"
    provenance = item.get("provenance") or []
    for record in provenance:
        if isinstance(record, dict) and record.get("writer"):
            blob = record["writer"]
            if isinstance(blob, dict):
                return f"writer={blob.get('kind')}:{blob.get('id')}"
    return "writer=unknown"


def _active_hypotheses_content(active: list[dict[str, Any]]) -> tuple[str, list[str]]:
    if not active:
        return "none recorded", []
    grouped: dict[str, list[dict[str, Any]]] = {}
    ids: list[str] = []
    for item in sorted(
        active, key=lambda row: (str(row.get("origin") or ""), str(row.get("hypothesis_id") or ""))
    ):
        origin = str(item.get("origin") or "unknown")
        grouped.setdefault(origin, []).append(item)
        identifier = str(item.get("hypothesis_id") or item.get("id") or "")
        if identifier:
            ids.append(identifier)
    lines: list[str] = []
    for origin in sorted(grouped):
        lines.append(f"origin={origin}")
        for item in grouped[origin]:
            status = str(item.get("status") or "unknown")
            claim = str(item.get("claim") or "unspecified")
            question = str(item.get("open_question") or item.get("question") or "")
            open_q = f" open_question={question}" if question else ""
            lines.append(f"  {status} {_writer_identity(item)}: {claim}{open_q}")
    return "\n".join(lines), ids


def _dead_ends_content(
    dead: list[dict[str, Any]],
    view: GraphView,
) -> tuple[str, list[str]]:
    lines: list[str] = []
    ids: list[str] = []
    for item in sorted(dead, key=lambda row: str(row.get("hypothesis_id") or row.get("id") or "")):
        killed = item.get("killed_dimensions") or item.get("killed_dimension") or []
        if isinstance(killed, str):
            killed_text = killed
        else:
            killed_text = ",".join(str(part) for part in killed) if killed else "none recorded"
        identifier = str(item.get("hypothesis_id") or item.get("id") or "")
        lines.append(
            f"falsified {_writer_identity(item)} {item.get('claim') or 'unspecified'}; "
            f"killed_dimensions={killed_text}; do not silently re-propose killed paths"
        )
        if identifier:
            ids.append(identifier)
    for item in sorted(view.dead_ends, key=lambda row: str(row.get("approach") or ""))[:8]:
        lines.append(f"{item.get('approach', 'approach')}: {item.get('reason', 'rejected')}")
        if item.get("id"):
            ids.append(str(item["id"]))
    if view.contradictions:
        for item in sorted(view.contradictions, key=lambda row: str(row.get("id") or ""))[:8]:
            lines.append(f"{item.get('kind', 'conflict')}:{item.get('left')}/{item.get('right')}")
            if item.get("id"):
                ids.append(str(item["id"]))
    return ("; ".join(lines) if lines else "none recorded"), ids


def _untried_content(view: GraphView, census: dict[str, Any], coverage_bits: list[str]) -> str:
    matrix = "; ".join(coverage_bits) if coverage_bits else "none recorded"
    remainder = census.get("unexamined") or []
    census_bit = ", ".join(remainder) if remainder else "empty"
    return (
        f"coverage-matrix remainder: {matrix}. "
        f"census remainder (M={census['census_total']} N={census['census_examined']}): {census_bit}"
    )


def _mechanism_cards_section(view: GraphView, policy: str) -> dict[str, Any] | None:
    if policy != "graph_aware":
        return None
    pragma = ""
    blob_parts: list[str] = []
    for unit in view.source_units:
        text = str(unit.get("source") or unit.get("text") or "")
        blob_parts.append(text)
        blob_parts.append(str(unit.get("name") or ""))
        if not pragma:
            match = re.search(r"pragma solidity\s+([^;]+)", text)
            if match:
                pragma = match.group(1).strip()
    blob = " ".join(blob_parts).lower()
    matched: list[str] = []
    ids: list[str] = []
    cards = list(view.global_mechanisms) + list(view.global_incidents) + list(view.global_patterns)
    for card in sorted(cards, key=lambda row: str(row.get("id") or row.get("title") or "")):
        solc_pred = str(card.get("solc_version") or card.get("solc") or "").strip()
        pattern = str(card.get("pattern") or card.get("applicability") or "").strip()
        # Signal-keyed: a card is applicable only when it carries a predicate
        # (solc version and/or pattern) that matches target facts.
        if not solc_pred and not pattern:
            continue
        if solc_pred and not _solc_predicate_holds(solc_pred, pragma):
            continue
        if pattern and pattern.lower() not in blob and pattern not in json.dumps(view.maps):
            continue
        matched.append(str(card.get("title") or card.get("name") or card.get("id") or "card"))
        if card.get("id"):
            ids.append(str(card["id"]))
    if not matched:
        return None
    return _section(
        "HISTORICAL_REFERENCE",
        "Applicable mechanism cards",
        "; ".join(matched),
        ids,
    )


def _solc_predicate_holds(predicate: str, pragma: str) -> bool:
    if not pragma:
        return False
    compact_pred = predicate.replace(" ", "")
    compact_pragma = pragma.replace(" ", "")
    if compact_pred in compact_pragma or compact_pred.strip("^<>=~") in compact_pragma:
        return True
    pred_ver = re.search(r"(\d+\.\d+(?:\.\d+)?)", predicate)
    prag_ver = re.search(r"(\d+\.\d+(?:\.\d+)?)", pragma)
    if pred_ver and prag_ver:
        return pred_ver.group(1) in prag_ver.group(1) or prag_ver.group(1).startswith(
            pred_ver.group(1).rsplit(".", 1)[0]
        )
    return False


def _money_map_content(view: GraphView) -> str:
    surface = view.maps.get("attack_surface") or {}
    value_flow = view.maps.get("value_flow") or {}
    raw_invariants = value_flow.get("invariants")
    raw_lifecycles = value_flow.get("lifecycles")
    raw_cohorts = value_flow.get("cohorts")
    invariants: list[Any] = list(raw_invariants) if isinstance(raw_invariants, list) else []
    lifecycles: list[Any] = list(raw_lifecycles) if isinstance(raw_lifecycles, list) else []
    cohorts: list[Any] = list(raw_cohorts) if isinstance(raw_cohorts, list) else []
    lines: list[str] = [
        "Money-map summary (0xsimao money-map-before-lenses; bundle <=200 lines).",
        "assets: "
        + ", ".join(
            str(item)
            for item in (surface.get("state_variables") or value_flow.get("assets") or ["native/ETH"])[:16]
        ),
        "tracked totals: "
        + json.dumps(value_flow.get("totals") or value_flow.get("concentration_points") or [], sort_keys=True)[:800],
        "invariants: " + ("; ".join(str(item) for item in invariants[:8]) or "none recorded"),
        "lifecycles: " + ("; ".join(str(item) for item in lifecycles[:8]) or "mint/transfer/burn unstated"),
        "cohorts: " + ("; ".join(str(item) for item in cohorts[:8]) or "no distinct entry cohorts recorded"),
        "asymmetry table (who / what / vs-whom):",
    ]
    flows = value_flow.get("flows") if isinstance(value_flow.get("flows"), list) else []
    if flows:
        for flow in flows:
            if isinstance(flow, dict):
                lines.append(
                    f"  {flow.get('function') or flow.get('from') or '?'} | "
                    f"{flow.get('kind') or flow.get('asset') or 'value'} | "
                    f"asymmetric={flow.get('asymmetric')}"
                )
            else:
                lines.append(f"  {flow}")
    else:
        for item in surface.get("entry_points") or []:
            if isinstance(item, dict):
                lines.append(
                    f"  {item.get('name')} | payable={item.get('payable')} | "
                    f"value_flow={item.get('value_flow')}"
                )
    if len(lines) > MONEY_MAP_LINE_CAP:
        lines = lines[: MONEY_MAP_LINE_CAP - 1]
        lines.append("(truncated at 200-line cap)")
    text = "\n".join(lines)
    if len(text) > 16000:
        clipped = "\n".join(lines)
        trimmed: list[str] = []
        used = 0
        for line in clipped.split("\n"):
            if used + len(line) + 1 > 15940:
                break
            trimmed.append(line)
            used += len(line) + 1
        if "(truncated at 200-line cap)" not in trimmed:
            trimmed.append("(truncated at 200-line cap)")
        text = "\n".join(trimmed)
    return text


def _coupled_content(pairs: list[dict[str, Any]]) -> str:
    lines = [
        "Coupled-state pair inventory (Nemesis: if four sides update and one does not, that is the bug)."
    ]
    for pair in pairs:
        lines.append(
            f"{pair['state_name']} ({pair['state_id']}): " + "; ".join(pair["mutation_status"])
        )
    return "\n".join(lines)


def _advisory_footer(view: GraphView, remaining: dict[str, int]) -> str:
    strikes = json.dumps(dict(sorted(view.payload_strikes.items())), sort_keys=True, separators=(",", ":"))
    quarantined = ",".join(sorted(str(item) for item in view.quarantined_sources)) or "none"
    budgets = ", ".join(f"{name}={remaining.get(name, 0)}" for name in remaining)
    return (
        f"advisory footer: budget_remaining[{budgets}]; "
        f"strikes={strikes}; quarantined={quarantined}; "
        f"anchoring_freeze_count={len(view.freeze_snapshots)}"
    )


def _scan_sections(
    sections: list[dict[str, Any]],
    extra_patterns: tuple[str, ...],
) -> list[dict[str, Any]]:
    """Pack-wide injection scan. Flagged content renders a placeholder; never silently dropped."""

    scanned: list[dict[str, Any]] = []
    flagged_titles: list[str] = []
    for section in sections:
        content = str(section.get("content") or "")
        if looks_like_injection(content, extra_patterns):
            flagged_titles.append(str(section.get("title") or ""))
            replacement = QUARANTINE_PLACEHOLDER.format(reason="injection")
            scanned.append({**section, "content": replacement})
        else:
            scanned.append(section)
    present = {str(item.get("title") or "") for item in scanned}
    missing = [title for title in flagged_titles if title not in present]
    if missing:
        raise CompileError(f"silent drop of quarantined sections: {missing}")
    for item in scanned:
        if QUARANTINE_MARK in str(item.get("content") or "") and not str(item.get("content") or "").strip():
            raise CompileError("quarantined section rendered empty")
    return scanned


def _clip(text: str, limit: int = 1200) -> str:
    stripped = " ".join(text.split())
    if not stripped:
        return "none recorded"
    if len(stripped) <= limit:
        return stripped
    return stripped[: limit - 1] + "…"


def _clip_multiline(text: str, limit: int = 16000) -> str:
    stripped = text.replace("\r\n", "\n").strip()
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
    *,
    preserve_lines: bool = False,
) -> dict[str, Any]:
    unique_ids = sorted({item for item in source_ids if item and _ID_OK.fullmatch(item)})[:256]
    body = _clip_multiline(content, 16000) if preserve_lines else _clip(content, 16000)
    return {
        "classification": classification,
        "title": title[:256],
        "content": body,
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
    extra_protected: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    omitted = {"target": 0, "global": 0, "learning": 0}
    protected = {title.lower() for title in RECONSTRUCTION_TITLES}
    protected.add("scope")
    protected.add("entry point census")
    for title in extra_protected or set():
        protected.add(title.lower())

    def tokens() -> int:
        return sum(estimate_section_tokens(item["title"], item["content"]) for item in sections)

    while tokens() > token_budget and len(sections) > 6:
        drop_at = None
        for index in range(len(sections) - 1, -1, -1):
            title = str(sections[index]["title"])
            if title.lower() not in protected:
                drop_at = index
                break
        if drop_at is None:
            break
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
    grouped_active, grouped_ids = _active_hypotheses_content(active)
    lead_text, lead_ids = _claims(leads, "none recorded")
    dead_text, dead_ids = _claims(dead, "none recorded")
    dead_ends_text, dead_end_ids = _dead_ends_content(dead, view)
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
    census = census_from_view(view)
    if census["census_total"] < census["census_examined"] or census["census_examined"] < 0:
        raise CompileError(
            f"INV-5.8 census arithmetic failed: M={census['census_total']} "
            f"N={census['census_examined']}"
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
    untried = _untried_content(view, census, coverage_bits)
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

    remaining = remaining_from_view(view)
    census_content = (
        f"census_total=M={census['census_total']}; "
        f"census_examined=N={census['census_examined']}; "
        f"unexamined={', '.join(census['unexamined']) if census['unexamined'] else 'empty'}"
    )
    sections: list[dict[str, Any]] = [
        _section("POLICY", "Scope", policy_content, [view.scope_id] if view.scope_id else []),
        _section("DETERMINISTIC_FACT", "Audit context", audit_context, []),
        _section(
            "DETERMINISTIC_FACT",
            "Entry Point Census",
            census_content,
            coverage_ids[:16],
        ),
        _section("HYPOTHESIS", "Active hypothesis", active_text, active_ids),
        _section("HYPOTHESIS", "Active hypotheses", grouped_active, grouped_ids or active_ids, preserve_lines=True),
        _section("RUNTIME_OBSERVATION", "Result so far", evidence_text, evidence_ids),
        _section("DETERMINISTIC_FACT", "Next action", next_action, []),
        _section("COUNTEREVIDENCE", "Dead approaches", dead_text, dead_ids),
        _section("COUNTEREVIDENCE", "Dead ends", dead_ends_text, dead_end_ids or dead_ids, preserve_lines=True),
        _section("ASSUMPTION", "Untried dimensions", untried, coverage_ids or question_ids),
        _section("DETERMINISTIC_FACT", "Coverage summary", coverage_summary, coverage_ids),
        _section("DETERMINISTIC_FACT", "Known facts", facts_text, fact_ids),
        _section("ASSUMPTION", "Assumptions", assumptions_text, []),
        _section("ASSUMPTION", "Open questions", question_text, question_ids),
        _section("HYPOTHESIS", "Unverified leads", lead_text, lead_ids),
    ]
    cards = _mechanism_cards_section(view, policy)
    if cards is not None:
        sections.append(cards)
    if retrieved_text and policy == "graph_aware":
        sections.append(
            _section("HISTORICAL_REFERENCE", "Retrieved context", retrieved_text, retrieved_ids)
        )
    elif policy != "graph_aware":
        # Explicitly absent: historical references are not facts.
        pass
    if money_map_signaled(view):
        sections.append(
            _section("DETERMINISTIC_FACT", "Money-map summary", _money_map_content(view), [], preserve_lines=True)
        )
    pairs = coupled_state_pairs(view)
    if pairs:
        pair_ids = [str(item["state_id"]) for item in pairs]
        sections.append(
            _section(
                "DETERMINISTIC_FACT",
                "Coupled-state pair inventory",
                _coupled_content(pairs),
                pair_ids,
                preserve_lines=True,
            )
        )
    extra_protected: set[str] = set()
    # INV-5.8: a non-empty census remainder requires the coverage lens in this pack.
    # Other lens blocks stay advisory on the router path and are not forced into the
    # pack, so reconstruction titles still fit the 512-token tiny-pack contract.
    if census["unexamined"]:
        coverage_block = compile_lens_blocks(view, remaining=remaining)["coverage"]
        sections.append(
            _section(
                "ASSUMPTION",
                coverage_block.title,
                coverage_block.guidance,
                coverage_block.citations,
                preserve_lines=True,
            )
        )
        extra_protected.add(coverage_block.title)
    sections.append(
        _section("DETERMINISTIC_FACT", "Advisory footer", _advisory_footer(view, remaining), [])
    )
    for section in sections:
        if QUARANTINE_MARK in str(section.get("content") or ""):
            extra_protected.add(str(section["title"]))

    sections = _scan_sections(sections, ())
    for section in sections:
        if QUARANTINE_MARK in str(section.get("content") or ""):
            extra_protected.add(str(section["title"]))
    if census["unexamined"]:
        titles = {str(item["title"]) for item in sections}
        if "Lens: coverage" not in titles:
            raise CompileError("INV-5.8: non-empty census remainder requires the coverage lens")
    sections, omitted = _trim_to_budget(sections, budget, extra_protected)
    if census["unexamined"]:
        titles = {str(item["title"]) for item in sections}
        if "Lens: coverage" not in titles:
            raise CompileError("INV-5.8: coverage lens silently dropped")
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
