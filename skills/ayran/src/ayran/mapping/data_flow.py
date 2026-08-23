"""Function-scoped data-flow: WRITES/READS from body spans, not whole-file blobs.

Known false-positive traps this pass does NOT solve (documented, not hidden):

- Same-name shadowed locals declared without a leading Solidity type keyword
  (``balances = 1`` inside a function is attributed as a state write).
- Writes via struct members ``s.field =`` are attributed to ``s`` only when
  ``s`` is a state variable; nested field names are not tracked.
- Assembly blocks (``assembly { sstore(...) }``) are opaque.
- String/comment masking is fixture-grade, not a full Solidity lexer.

Deliberate Nemesis-scope choice: ``constant`` / ``immutable`` state targets
emit no WRITES. They cannot diverge post-construction.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ayran.context.ids import DEFAULT_CLUSTER_ID, DEFAULT_RUN_ID
from ayran.mapping.attack_surface import build_attack_surface
from ayran.mapping.types import call_edge, map_summary_node

PINNED = "2026-08-12T12:00:00Z"

_TYPE_DECL_RE = (
    r"(?:mapping\s*\([^)]*\)|address(?:\s+payable)?|u?int\d*|int|uint|bool|"
    r"bytes\d*|string|bytes)\s+"
    r"(?:public|private|internal|memory|storage|calldata|constant|immutable|\s)*"
)


def _prop(node: dict[str, Any], name: str) -> str:
    for item in node.get("properties") or []:
        if item.get("name") == name:
            return str(item.get("value") or "")
    return ""


def _ident(name: str) -> str:
    return rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])"


def _line_declares(line: str, name: str) -> bool:
    return bool(re.search(_TYPE_DECL_RE + _ident(name) + r"\s*(?:=|;)", line))


def _write_on_line(line: str, name: str) -> bool:
    ident = _ident(name)
    if re.search(ident + r"\s*(?:\+\+|--)", line) or re.search(r"(?:\+\+|--)\s*" + ident, line):
        return True
    if re.search(ident + r"\s*\.\s*(?:push|pop)\s*\(", line):
        return True
    if re.search(ident + r"\s*\[[^\n;]*\]\s*(?:\+=|-=|\*=|/=|=(?!=))", line):
        return True
    return bool(re.search(ident + r"\s*(?:\+=|-=|\*=|/=|=(?!=))", line))


def _body_writes(body: str, name: str) -> bool:
    for line in body.split("\n"):
        if _line_declares(line, name):
            continue
        if _write_on_line(line, name):
            return True
    return False


def _body_reads(body: str, name: str) -> bool:
    ident = re.compile(_ident(name))
    for line in body.split("\n"):
        if _line_declares(line, name):
            continue
        if _write_on_line(line, name):
            continue
        if ident.search(line):
            return True
    return False


def _parsed_functions(surface: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (str(item.get("name") or ""), str(item.get("locator") or "")): item
        for item in surface.get("functions") or []
    }


def _state_flags(surface: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item.get("name") or ""): item for item in surface.get("state_variables") or []}


def build_data_flow(
    *,
    cluster_id: str = DEFAULT_CLUSTER_ID,
    run_id: str = DEFAULT_RUN_ID,
    created_at: str = PINNED,
    source_text: str | None = None,
    source_units: list[dict[str, Any]] | None = None,
    slither_json: dict[str, Any] | None = None,
    locator: str = "target/src/Contract.sol",
) -> dict[str, Any]:
    surface = build_attack_surface(
        cluster_id=cluster_id,
        run_id=run_id,
        created_at=created_at,
        source_text=source_text,
        source_units=source_units,
        slither_json=slither_json,
        locator=locator,
    )
    fn_nodes = [node for node in surface["nodes"] if node.get("node_type") == "Function"]
    state_nodes = [node for node in surface["nodes"] if node.get("node_type") == "StateVariable"]
    parsed = _parsed_functions(surface)
    flags = _state_flags(surface)
    edges: list[dict[str, Any]] = []
    taint: list[dict[str, str]] = []
    for fn in sorted(fn_nodes, key=lambda node: str(node.get("node_id") or "")):
        name = _prop(fn, "name")
        fn_locator = str(fn.get("source_locator") or "")
        record = parsed.get((name, fn_locator)) or {}
        body = str(record.get("body") or "")
        if not name or not body:
            continue
        for state in sorted(state_nodes, key=lambda node: str(node.get("node_id") or "")):
            var = _prop(state, "name")
            if not var:
                continue
            meta = flags.get(var) or {}
            frozen = bool(meta.get("constant") or meta.get("immutable"))
            writes = False if frozen else _body_writes(body, var)
            reads = _body_reads(body, var)
            if reads:
                edges.append(
                    call_edge(
                        source_id=str(fn["node_id"]),
                        target_id=str(state["node_id"]),
                        run_id=run_id,
                        created_at=created_at,
                        locator=locator,
                        edge_type="READS",
                    )
                )
            if writes:
                edges.append(
                    call_edge(
                        source_id=str(fn["node_id"]),
                        target_id=str(state["node_id"]),
                        run_id=run_id,
                        created_at=created_at,
                        locator=locator,
                        edge_type="WRITES",
                    )
                )
                taint.append({"source": name, "sink": var, "kind": "state_write"})
    unique = {str(edge["edge_id"]): edge for edge in edges}
    edges = [unique[key] for key in sorted(unique)]
    taint = sorted(taint, key=lambda row: (row["source"], row["sink"], row["kind"]))[:32]
    payload = json.dumps(
        {"cluster_id": cluster_id, "taint": taint, "edge_count": len(edges)},
        sort_keys=True,
        separators=(",", ":"),
    )
    summary = map_summary_node(
        map_type="DataFlowMap",
        cluster_id=cluster_id,
        run_id=run_id,
        created_at=created_at,
        payload=payload,
        extra={"edge_count": len(edges)},
    )
    return {
        "map_type": "data_flow",
        "cluster_id": cluster_id,
        "nodes": fn_nodes + state_nodes + [summary],
        "edges": edges,
        "taint": taint,
        "payload": json.loads(payload),
    }
