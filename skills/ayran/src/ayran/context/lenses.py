"""Six advisory lenses replacing hypothesis drivers (spec §5.2, INV-5.2/5.3/5.4).

Pure functions of GraphView: lenses never fabricate Hypothesis nodes. Budget
numbers mirror hypotheses.builders.ORIGIN_BUDGET exactly (25/15/15/10/15/20).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ayran.context.ids import content_id
from ayran.context.serialize import estimate_tokens
from ayran.context.view import GraphView
from ayran.graph.canonical import canonical_hash

LENS_NAMES = (
    "first_principles",
    "precedent",
    "contradiction",
    "tool_signal",
    "coverage",
    "specialist",
)

LENS_BUDGETS = {
    "first_principles": 25,
    "precedent": 15,
    "contradiction": 15,
    "tool_signal": 10,
    "coverage": 15,
    "specialist": 20,
}

LENS_ORIGINS = {
    "first_principles": "model_novel",
    "precedent": "global_graph",
    "contradiction": "contradiction",
    "tool_signal": "tool",
    "coverage": "coverage",
    "specialist": "specialist",
}

ALWAYS_ON_LENSES = frozenset({"contradiction", "coverage"})
PRECEDENT_SUPPRESS_POLICIES = frozenset({"target_only", "knowledge_blind"})
LENS_TOKEN_CAP = 1200
QUARANTINE_PLACEHOLDER = "[QUARANTINED: {reason}]"
WRITE_EDGE_TYPES = frozenset({"WRITES", "WRITE", "MUTATES", "SETS", "UPDATES"})
SPECIALIST_ROLES = (
    "devils-advocate",
    "gate-b-skeptic",
    "econ-analyst",
    "state-coupling-auditor",
    "code-reviewer",
    "access-control-analyst",
    "boundary-provenance-auditor",
    "x-ray-invariant-synthesist",
    "formal-methods",
    "fuzz-harness-engineer",
    "attack-mapper",
    "bug-hunter",
    "precedent-analyst",
    "coverage-auditor",
)

# Census cell statuses that count as examined (INV-5.8).
EXAMINED_CELL_STATUSES = frozenset({"examined", "accepted_residual_risk"})


@dataclass(slots=True)
class LensBlock:
    """Advisory lens block. Not a Hypothesis; carries no claim authorship."""

    lens: str
    title: str
    guidance: str
    budget_remaining: int
    citations: list[str] = field(default_factory=list)
    suppressed: bool = False
    quarantined: bool = False
    always_on: bool = False
    material: bool = False
    units_spent: int = 0
    payload_only: bool = False
    coverage_deltas: list[dict[str, Any]] = field(default_factory=list)
    advised_roles: list[str] = field(default_factory=list)
    stop_reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "lens": self.lens,
            "title": self.title,
            "guidance": self.guidance,
            "budget_remaining": self.budget_remaining,
            "citations": list(self.citations),
            "suppressed": self.suppressed,
            "quarantined": self.quarantined,
            "always_on": self.always_on,
            "material": self.material,
            "units_spent": self.units_spent,
            "payload_only": self.payload_only,
            "coverage_deltas": list(self.coverage_deltas),
            "advised_roles": list(self.advised_roles),
            "stop_reason": self.stop_reason,
            "fingerprint": canonical_hash(
                {
                    "lens": self.lens,
                    "title": self.title,
                    "guidance": self.guidance,
                    "citations": list(self.citations),
                    "suppressed": self.suppressed,
                    "quarantined": self.quarantined,
                }
            ),
        }


def remaining_from_view(view: GraphView) -> dict[str, int]:
    """Advisory remaining units per lens, derived from persisted DriverState spend."""

    spent = {
        name: int((view.driver_states.get(name) or {}).get("spend") or 0) for name in LENS_NAMES
    }
    released = bool((view.budget_state or {}).get("reserve_released"))
    leftover_tranche = max(0, 100 - sum(spent.values()))
    reserved = 0 if released else max(0, LENS_BUDGETS["first_principles"] - spent["first_principles"])
    result: dict[str, int] = {}
    for name, ceiling in LENS_BUDGETS.items():
        cap_left = max(0, ceiling - spent[name])
        if name != "first_principles" and not released:
            cap_left = min(cap_left, max(0, leftover_tranche - reserved))
        else:
            cap_left = min(cap_left, leftover_tranche)
        result[name] = cap_left
    return result


def _node_name(node: dict[str, Any]) -> str:
    for item in node.get("properties") or []:
        if isinstance(item, dict) and item.get("name") in {"name", "title"}:
            value = str(item.get("value") or "").strip()
            if value:
                return value
    return str(node.get("node_id") or "")


def _prop(node: dict[str, Any], name: str) -> Any:
    for item in node.get("properties") or []:
        if isinstance(item, dict) and item.get("name") == name:
            return item.get("value")
    return None


def _entry_points(view: GraphView) -> list[Any]:
    surface = view.maps.get("attack_surface") or {}
    raw = surface.get("entry_points")
    if isinstance(raw, list):
        return list(raw)
    return []


def entry_point_names(view: GraphView) -> list[str]:
    names: list[str] = []
    for item in _entry_points(view):
        if isinstance(item, dict):
            name = str(item.get("name") or item.get("id") or "").strip()
        else:
            name = str(item).strip()
        if name:
            names.append(name)
    return names


def census_from_view(view: GraphView) -> dict[str, Any]:
    """INV-5.8 census: M = len(entry_points), N = examined entry_points:* cells.

    Fail-closed arithmetic (M < N or N < 0) is raised by the pack compiler, not
    here, so callers can inspect the raw counts.
    """

    names = entry_point_names(view)
    census_total = len(names)
    examined_names: list[str] = []
    examined_cells = 0
    for cell in view.coverage_cells:
        dimension = str(cell.get("dimension") or "")
        status = str(cell.get("status") or "")
        if not dimension.startswith("entry_points:"):
            continue
        if status not in EXAMINED_CELL_STATUSES:
            continue
        examined_cells += 1
        examined_names.append(dimension.split(":", 1)[1])
    unexamined = sorted(set(names) - set(examined_names))
    return {
        "census_total": census_total,
        "census_examined": examined_cells,
        "unexamined": unexamined,
        "entry_point_names": names,
        "examined_names": examined_names,
    }


def money_map_signaled(view: GraphView) -> bool:
    """Accounting-signal rule (pure function of GraphView; Scope D).

    Signaled when ANY attack_surface entry_point dict has payable or value_flow
    truthy, OR the value_flow map payload is a non-empty dict.
    """

    value_flow = view.maps.get("value_flow")
    if isinstance(value_flow, dict) and value_flow:
        return True
    for item in _entry_points(view):
        if isinstance(item, dict) and (item.get("payable") or item.get("value_flow")):
            return True
    return False


def coupled_state_pairs(view: GraphView) -> list[dict[str, Any]]:
    """State variables written by more than one function.

    Edge-type matching: an edge participates iff ``edge_type`` is in
    WRITE_EDGE_TYPES ({WRITES, WRITE, MUTATES, SETS, UPDATES}). The Function
    endpoint is treated as the writer and the StateVariable endpoint as the
    written variable, regardless of source/target orientation.
    """

    nodes: dict[str, tuple[str, str]] = {}
    for node in view.nodes:
        identifier = str(node.get("node_id") or "")
        if not identifier:
            continue
        nodes[identifier] = (str(node.get("node_type") or ""), _node_name(node) or identifier)
    writers: dict[str, list[str]] = {}
    for edge in view.edges:
        edge_type = str(edge.get("edge_type") or "")
        if edge_type not in WRITE_EDGE_TYPES:
            continue
        source = str(edge.get("source_id") or "")
        target = str(edge.get("target_id") or "")
        source_type, _source_name = nodes.get(source, ("", ""))
        target_type, _target_name = nodes.get(target, ("", ""))
        function_id = ""
        state_id = ""
        if source_type == "Function" and target_type == "StateVariable":
            function_id, state_id = source, target
        elif target_type == "Function" and source_type == "StateVariable":
            function_id, state_id = target, source
        if function_id and state_id:
            bucket = writers.setdefault(state_id, [])
            if function_id not in bucket:
                bucket.append(function_id)
    pairs: list[dict[str, Any]] = []
    for state_id, function_ids in sorted(writers.items()):
        if len(function_ids) < 2:
            continue
        _stype, state_name = nodes.get(state_id, ("StateVariable", state_id))
        updated = []
        for function_id in sorted(function_ids):
            _ftype, function_name = nodes.get(function_id, ("Function", function_id))
            updated.append(f"updated by {function_id} ({function_name})")
        pairs.append(
            {
                "state_id": state_id,
                "state_name": state_name,
                "function_ids": sorted(function_ids),
                "mutation_status": updated,
            }
        )
    return pairs


def _anchor_citations(view: GraphView, extra: list[str] | None = None) -> list[str]:
    citations: list[str] = []
    for item in extra or []:
        if item and item not in citations:
            citations.append(item)
    for node in sorted(view.nodes, key=lambda row: str(row.get("node_id") or "")):
        identifier = str(node.get("node_id") or "")
        if identifier and identifier not in citations:
            citations.append(identifier)
        if len(citations) >= 8:
            return citations[:8]
    for cell in sorted(view.coverage_cells, key=lambda row: str(row.get("coverage_cell_id") or "")):
        identifier = str(cell.get("coverage_cell_id") or "")
        if identifier and identifier not in citations:
            citations.append(identifier)
        if len(citations) >= 8:
            return citations[:8]
    if not citations:
        citations.append(content_id("nod", "lens-anchor", view.cluster_id))
    return citations[:8]


def _cap_guidance(title: str, guidance: str) -> str:
    text = guidance.strip() or "none recorded"
    # Conservative: UTF-8 chars/4 (serialize.estimate_tokens). Leave headroom for title.
    budget_chars = max(32, LENS_TOKEN_CAP * 4 - len(title) - 8)
    if len(text) > budget_chars:
        text = text[: budget_chars - 1] + "…"
    while estimate_tokens(f"{title}\n{text}") > LENS_TOKEN_CAP and len(text) > 8:
        text = text[: max(8, len(text) - 32)].rstrip() + "…"
    return text


def _looks_like_injection(text: str, extra: tuple[str, ...] = ()) -> bool:
    # Lazy import: ayran.router.__init__ pulls engine, which imports this module.
    from ayran.router.injection import looks_like_injection

    return looks_like_injection(text, extra)


def _inputs_flagged(view: GraphView, extra_patterns: tuple[str, ...] = ()) -> bool:
    blobs: list[str] = []
    for unit in view.source_units:
        blobs.append(str(unit.get("source") or unit.get("text") or unit.get("name") or ""))
    for item in view.hypotheses:
        blobs.append(str(item.get("claim") or ""))
        for step in item.get("attack_path") or []:
            blobs.append(str(step))
    for run in view.tool_runs:
        blobs.append(str(run.get("tool_name") or ""))
        blobs.append(str(run.get("summary") or ""))
    for card in view.global_mechanisms + view.global_incidents + view.global_patterns:
        blobs.append(str(card.get("title") or card.get("name") or ""))
    return any(_looks_like_injection(blob, extra_patterns) for blob in blobs if blob)


def _target_first_complete(view: GraphView) -> bool:
    high_value = view.high_value_clusters or [view.cluster_id]
    return all(item in view.target_first_completed for item in high_value)


def precedent_suppressed(view: GraphView) -> bool:
    if view.knowledge_policy in PRECEDENT_SUPPRESS_POLICIES:
        return True
    return not _target_first_complete(view)


def _advised_roles(view: GraphView) -> list[str]:
    roles: list[str] = []
    if view.contradictions or any(
        str(item.get("status") or "") in {"lead", "supported", "poc_worthy"} for item in view.hypotheses
    ):
        roles.append("devils-advocate")
    census = census_from_view(view)
    if census["unexamined"] or any(
        str(cell.get("status") or "") not in EXAMINED_CELL_STATUSES for cell in view.coverage_cells
    ):
        roles.append("coverage-auditor")
    if view.tool_runs:
        roles.append("code-reviewer")
    if money_map_signaled(view):
        roles.append("econ-analyst")
    if coupled_state_pairs(view):
        roles.append("state-coupling-auditor")
    if not roles:
        roles.append("attack-mapper")
    unique: list[str] = []
    for role in roles:
        if role in SPECIALIST_ROLES and role not in unique:
            unique.append(role)
    return unique[:3]


def _block(
    *,
    lens: str,
    title: str,
    guidance: str,
    view: GraphView,
    remaining: dict[str, int],
    citations: list[str],
    extra_patterns: tuple[str, ...],
    coverage_deltas: list[dict[str, Any]] | None = None,
    advised_roles: list[str] | None = None,
    suppressed: bool = False,
) -> LensBlock:
    flagged = _inputs_flagged(view, extra_patterns) or _looks_like_injection(guidance, extra_patterns)
    text = (
        QUARANTINE_PLACEHOLDER.format(reason="injection")
        if flagged
        else _cap_guidance(title, guidance)
    )
    cites = _anchor_citations(view, citations)
    return LensBlock(
        lens=lens,
        title=title,
        guidance=text,
        budget_remaining=int(remaining.get(lens, 0)),
        citations=cites,
        suppressed=suppressed,
        quarantined=flagged,
        always_on=lens in ALWAYS_ON_LENSES,
        material=not suppressed and not flagged,
        payload_only=flagged,
        coverage_deltas=list(coverage_deltas or []),
        advised_roles=list(advised_roles or []),
        stop_reason="quarantined" if flagged else ("suppressed" if suppressed else ""),
    )


def _first_principles(view: GraphView, remaining: dict[str, int], extra: tuple[str, ...]) -> LensBlock:
    entries = entry_point_names(view)
    writes = [
        str(node.get("node_id") or "")
        for node in view.nodes
        if node.get("node_type") in {"Function", "StateVariable"}
    ]
    citation_ids = [item for item in writes if item][:6]
    entry_text = ", ".join(entries[:12]) if entries else "no mapped entry points yet"
    guidance = (
        "first_principles (budget 25; inherits the protected model_novel reserve): "
        "derive conservation and authorization invariants from target material alone; "
        "invert assumptions per entry point; author via remember(origin=model_novel). "
        f"Entry points: {entry_text}. "
        "Cite attack-surface entry points, value-flow nodes, and Delta-write sites "
        "(pashov x-ray: unguarded write site = high-signal pointer). "
        "Do not retrieve historical cards in this lane."
    )
    return _block(
        lens="first_principles",
        title="Lens: first_principles",
        guidance=guidance,
        view=view,
        remaining=remaining,
        citations=citation_ids,
        extra_patterns=extra,
    )


def _precedent(view: GraphView, remaining: dict[str, int], extra: tuple[str, ...]) -> LensBlock:
    suppressed = precedent_suppressed(view)
    cards = list(view.global_mechanisms) + list(view.global_incidents)
    titles = [str(card.get("title") or card.get("name") or card.get("id") or "card") for card in cards[:8]]
    card_ids = [str(card.get("id") or "") for card in cards if card.get("id")]
    if suppressed:
        guidance = (
            "precedent lens SUPPRESSED under knowledge_policy "
            f"{view.knowledge_policy} and/or until target-first completion "
            "(engine.py lines 106-133 parity)."
        )
    else:
        listed = "; ".join(titles) if titles else "no mechanism/incident cards retrieved"
        guidance = (
            "precedent (budget 15): transfer analogies from cited mechanism/incident "
            "cards; state the novelty delta versus each cited precedent before "
            f"remember(). Cards: {listed}. Treat as HISTORICAL_REFERENCE, never as "
            "target evidence. Self-reported effectiveness numbers are claims."
        )
    block = _block(
        lens="precedent",
        title="Lens: precedent",
        guidance=guidance,
        view=view,
        remaining=remaining,
        citations=card_ids,
        extra_patterns=extra,
        suppressed=suppressed,
    )
    if suppressed:
        block.material = False
    return block


def _contradiction(view: GraphView, remaining: dict[str, int], extra: tuple[str, ...]) -> LensBlock:
    groups = list(view.contradictions)
    if not groups:
        guidance = (
            "contradiction (budget 15; ALWAYS-ON): no conflicting assertions are "
            f"recorded on cluster {view.cluster_id}. Keep a watcher on spec/code "
            "and map-vs-source discrepancies; resolve cited conflicts by experiment; "
            "outcomes end in remember() or a killed dimension."
        )
        citations: list[str] = []
    else:
        bits = []
        citations = []
        for group in groups[:8]:
            kind = str(group.get("kind") or "conflict")
            left = str(group.get("left") or "assertion-a")
            right = str(group.get("right") or "assertion-b")
            bits.append(f"{kind}: {left} vs {right}")
            if group.get("id"):
                citations.append(str(group["id"]))
        guidance = (
            "contradiction (budget 15; ALWAYS-ON): resolve cited conflicts by "
            "experiment; outcomes end in remember() or a killed dimension. "
            + "; ".join(bits)
        )
    return _block(
        lens="contradiction",
        title="Lens: contradiction",
        guidance=guidance,
        view=view,
        remaining=remaining,
        citations=citations,
        extra_patterns=extra,
    )


def _tool_signal(view: GraphView, remaining: dict[str, int], extra: tuple[str, ...]) -> LensBlock:
    leads: list[str] = []
    citations: list[str] = []
    for run in sorted(view.tool_runs, key=lambda row: str(row.get("tool_run_id") or "")):
        name = str(run.get("tool_name") or run.get("capability_id") or "tool")
        ceiling = str(run.get("evidence_ceiling") or "lead")
        leads.append(f"{name} ceiling={ceiling}")
        if run.get("tool_run_id"):
            citations.append(str(run["tool_run_id"]))
    guidance = (
        "tool_signal (budget 10): confirm/refute adapter leads along reachable "
        "paths; consult FP pools (scv-scan False Positives; zeroskills hard negatives) "
        "before trusting alerts. Budget per unrefuted lead engaged. "
    )
    if leads:
        guidance += "Unrefuted leads: " + "; ".join(leads[:8]) + "."
    else:
        guidance += f"No normalized tool leads on cluster {view.cluster_id}; mapping checks remain eligible but are not evidence of safety."
    return _block(
        lens="tool_signal",
        title="Lens: tool_signal",
        guidance=guidance,
        view=view,
        remaining=remaining,
        citations=citations,
        extra_patterns=extra,
    )


def _coverage(view: GraphView, remaining: dict[str, int], extra: tuple[str, ...]) -> LensBlock:
    census = census_from_view(view)
    deltas: list[dict[str, Any]] = []
    remainder_bits: list[str] = []
    citations: list[str] = []
    for cell in sorted(view.coverage_cells, key=lambda row: str(row.get("coverage_cell_id") or "")):
        status = str(cell.get("status") or "open")
        dimension = str(cell.get("dimension") or "unspecified")
        identifier = str(cell.get("coverage_cell_id") or "")
        if identifier:
            citations.append(identifier)
        if status not in EXAMINED_CELL_STATUSES and status != "blocked":
            remainder_bits.append(f"{dimension}={status}")
            deltas.append(
                {
                    "coverage_cell_id": identifier,
                    "new_state": "in_progress",
                    "dimension": dimension,
                }
            )
    unexamined = census["unexamined"]
    guidance = (
        "coverage (budget 15; ALWAYS-ON): select next untried cell; justify skips. "
        f"Census M={census['census_total']} N={census['census_examined']} "
        f"(DarkNavy denominator: coverage claims without M/N are invalid). "
        f"Census remainder: {', '.join(unexamined) if unexamined else 'empty'}. "
        f"Matrix remainder: {'; '.join(remainder_bits[:12]) if remainder_bits else 'none'}."
    )
    return _block(
        lens="coverage",
        title="Lens: coverage",
        guidance=guidance,
        view=view,
        remaining=remaining,
        citations=citations,
        extra_patterns=extra,
        coverage_deltas=deltas[:16],
    )


def _specialist(view: GraphView, remaining: dict[str, int], extra: tuple[str, ...]) -> LensBlock:
    roles = _advised_roles(view)
    children = [
        str(node.get("node_id") or "")
        for node in view.nodes
        if node.get("node_type") in {"ChildRunRecord", "SpecialistRun"} and node.get("node_id")
    ]
    guidance = (
        "specialist (budget 20): advise named-role rlm() spawns with forefy goal.v1 "
        "missions; converge independent lenses before upgrading "
        "([lenses: 2+] LEAD->FINDING upgrade requires >=2 independent lenses converging). "
        f"Advised roles: {', '.join(roles)}. "
        "Budget per advised spawn. Reuse RequestSpecialist. "
        "Specialists hold ZERO sidecar-write verbs."
    )
    return _block(
        lens="specialist",
        title="Lens: specialist",
        guidance=guidance,
        view=view,
        remaining=remaining,
        citations=children,
        extra_patterns=extra,
        advised_roles=roles,
    )


_BUILDERS = {
    "first_principles": _first_principles,
    "precedent": _precedent,
    "contradiction": _contradiction,
    "tool_signal": _tool_signal,
    "coverage": _coverage,
    "specialist": _specialist,
}


def compile_lens_blocks(
    view: GraphView,
    *,
    remaining: dict[str, int] | None = None,
    extra_patterns: tuple[str, ...] = (),
) -> dict[str, LensBlock]:
    """GraphView -> per-lens blocks. Identical view+remaining => identical blocks."""

    leftover = remaining if remaining is not None else remaining_from_view(view)
    blocks: dict[str, LensBlock] = {}
    for name in LENS_NAMES:
        blocks[name] = _BUILDERS[name](view, leftover, extra_patterns)
    return blocks
