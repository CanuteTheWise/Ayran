"""Value-transfer map from source structure, never model inference.

Payload keys consumed by ``_money_map_content``: assets, totals, lifecycles,
flows, concentration_points. ``invariants`` is omitted on purpose (model work,
not map work — the renderer prints "none recorded"). ``cohorts`` is omitted
unless a temporal ledger-struct pattern is matched; this pass does not emit
it (noisy on fixtures).

Asymmetric heuristic (a lead, not a verdict): credit-without-debit in the
same body — the function credits a ledger (``ledger[x] +=`` / ``ledger[x] =``)
with no ``-=``, or the function is payable / receive and never mentions a
ledger. Fabrication is forbidden; absent facts stay absent.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ayran.context.ids import DEFAULT_CLUSTER_ID, DEFAULT_RUN_ID
from ayran.mapping.attack_surface import build_attack_surface
from ayran.mapping.source import VALUE_RE
from ayran.mapping.types import call_edge, map_summary_node

PINNED = "2026-08-12T12:00:00Z"

LEDGER_RE = re.compile(
    r"mapping\s*\(\s*address\s*=>\s*(u?int\d*)\s*\)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_]\w*)",
    re.IGNORECASE,
)
ETH_RE = re.compile(r"\bmsg\.value\b|\.transfer\(|\.send\(|call\{value")
TOKEN_RE = re.compile(r"\bsafeTransfer\b|\btransferFrom\b|\.safeTransfer\s*\(")
MINT_RE = re.compile(r"\b_?mint\b")
BURN_RE = re.compile(r"\b_?burn\b")
TRANSFER_LIFE_RE = re.compile(r"\b(safeTransfer|transferFrom|safeTransferFrom)\b")
CREDIT_RE = r"\s*\[[^\n;]*\]\s*(?:\+=|=(?!=))"
DEBIT_RE = r"\s*\[[^\n;]*\]\s*-="


def _prop(node: dict[str, Any], name: str) -> str:
    for item in node.get("properties") or []:
        if item.get("name") == name:
            return str(item.get("value") or "")
    return ""


def _payable(node: dict[str, Any]) -> bool:
    return any(
        item.get("name") == "payable" and item.get("value") is True
        for item in node.get("properties") or []
    )


def _parsed_functions(surface: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (str(item.get("name") or ""), str(item.get("locator") or "")): item
        for item in surface.get("functions") or []
    }


def _ledgers(source: str, state_names: set[str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in LEDGER_RE.finditer(source):
        name = match.group(2)
        if name in state_names and name not in seen:
            seen.add(name)
            found.append(name)
    return sorted(found)


def _credits_without_debit(body: str, ledger: str) -> bool:
    ident = re.escape(ledger)
    credit = bool(re.search(rf"\b{ident}{CREDIT_RE}", body))
    debit = bool(re.search(rf"\b{ident}{DEBIT_RE}", body))
    return credit and not debit


def _kind(body: str, payable: bool, name: str) -> str:
    eth = payable or name == "receive" or bool(ETH_RE.search(body))
    token = bool(TOKEN_RE.search(body))
    if eth and token:
        return "eth+token"
    if token:
        return "token"
    return "eth"


def _value_bearing(body: str, payable: bool, name: str) -> bool:
    if payable or name == "receive":
        return True
    return bool(VALUE_RE.search(body) or ETH_RE.search(body) or TOKEN_RE.search(body))


def _lifecycles(functions: list[dict[str, Any]]) -> list[str]:
    verbs: set[str] = set()
    for item in functions:
        name = str(item.get("name") or "")
        body = str(item.get("body") or "")
        blob = f"{name}\n{body}"
        if MINT_RE.search(blob):
            verbs.add("mint")
        if BURN_RE.search(blob):
            verbs.add("burn")
        if TRANSFER_LIFE_RE.search(blob) or name in {"transfer", "transferFrom", "safeTransfer"}:
            verbs.add("transfer")
    return sorted(verbs)


def build_value_flow(
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
    blob = source_text or ""
    if source_units:
        blob = "\n".join(str(unit.get("source") or "") for unit in sorted(
            source_units, key=lambda row: str(row.get("locator") or row.get("path") or "")
        ))
    fn_nodes = [node for node in surface["nodes"] if node.get("node_type") == "Function"]
    parsed = _parsed_functions(surface)
    state_names = {str(item.get("name") or "") for item in surface.get("state_variables") or []}
    ledgers = _ledgers(blob, state_names)
    flows: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for fn in sorted(fn_nodes, key=lambda node: str(node.get("node_id") or "")):
        name = _prop(fn, "name")
        fn_locator = str(fn.get("source_locator") or "")
        record = parsed.get((name, fn_locator)) or {}
        body = str(record.get("body") or "")
        payable = _payable(fn) or bool(record.get("payable"))
        if not name or not _value_bearing(body, payable, name):
            continue
        kind = _kind(body, payable, name)
        mentioned = [ledger for ledger in ledgers if re.search(rf"\b{re.escape(ledger)}\b", body)]
        asymmetric = any(_credits_without_debit(body, ledger) for ledger in mentioned) or (
            (payable or name == "receive") and not mentioned
        )
        flow: dict[str, Any] = {
            "function": name,
            "kind": kind,
            "asymmetric": asymmetric,
        }
        if mentioned:
            flow["assets"] = mentioned
            flow["asset"] = mentioned[0]
        elif kind.startswith("eth"):
            flow["asset"] = "ETH"
        flows.append(flow)
        edges.append(
            call_edge(
                source_id=str(fn["node_id"]),
                target_id=str(fn["node_id"]),
                run_id=run_id,
                created_at=created_at,
                locator=locator,
                edge_type="TRANSFERS",
            )
        )
    unique = {str(edge["edge_id"]): edge for edge in edges}
    edges = [unique[key] for key in sorted(unique)]
    flows = sorted(flows, key=lambda row: str(row.get("function") or ""))
    has_eth = any(str(item.get("kind") or "").startswith("eth") or item.get("asset") == "ETH" for item in flows)
    assets: list[str] = []
    if has_eth:
        assets.append("ETH")
    assets.extend(ledgers)
    totals = [
        {
            "asset": name,
            "denominator": name,
            "note": "mapping(address=>...) balance ledger; sum-conservation candidate",
        }
        for name in ledgers
    ]
    lifecycles = _lifecycles(list(surface.get("functions") or []))
    if not assets and not flows and not totals and not lifecycles:
        payload_obj: dict[str, Any] = {}
    else:
        payload_obj = {
            "cluster_id": cluster_id,
            "assets": assets,
            "totals": totals,
            "flows": flows,
            "concentration_points": [item["function"] for item in flows],
        }
        if lifecycles:
            payload_obj["lifecycles"] = lifecycles
    payload = json.dumps(payload_obj, sort_keys=True, separators=(",", ":"))
    summary = map_summary_node(
        map_type="ValueFlowMap",
        cluster_id=cluster_id,
        run_id=run_id,
        created_at=created_at,
        payload=payload,
        extra={"flow_count": len(flows)},
    )
    return {
        "map_type": "value_flow",
        "cluster_id": cluster_id,
        "nodes": [*fn_nodes, summary],
        "edges": edges,
        "flows": flows,
        "payload": json.loads(payload) if payload else {},
    }
