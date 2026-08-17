"""Attack-surface map from source and Slither/solc facts."""

from __future__ import annotations

import json
from typing import Any

from ayran.context.ids import DEFAULT_CLUSTER_ID, DEFAULT_RUN_ID
from ayran.mapping.source import parse_solidity, parse_sources
from ayran.mapping.types import function_node, map_summary_node, state_node

PINNED = "2026-08-12T12:00:00Z"


def _functions_from_slither(payload: dict[str, Any]) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    detectors = ((payload.get("results") or {}).get("detectors") or []) if isinstance(payload.get("results"), dict) else payload.get("detectors") or []
    if not isinstance(detectors, list):
        detectors = []
    for detector in detectors:
        if not isinstance(detector, dict):
            continue
        for element in detector.get("elements") or []:
            if not isinstance(element, dict):
                continue
            if element.get("type") != "function":
                continue
            mapping = element.get("source_mapping") or {}
            file_name = str(
                mapping.get("filename_relative")
                or mapping.get("filename_short")
                or "unknown.sol"
            )
            line = 1
            lines = mapping.get("lines")
            if isinstance(lines, list) and lines:
                line = int(lines[0])
            functions.append(
                {
                    "name": str(element.get("name") or "unknown"),
                    "visibility": "public",
                    "payable": False,
                    "view": "view" in str(detector.get("description") or "").lower(),
                    "locator": f"{file_name}:{line}",
                    "check": str(detector.get("check") or ""),
                    "privileged": False,
                    "time_dependent": False,
                    "value_flow": False,
                    "external": True,
                }
            )
    functions.sort(key=lambda row: (row["locator"], row["name"]))
    return functions


def _functions_from_solc(payload: dict[str, Any]) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    contracts = payload.get("contracts") or {}
    if not isinstance(contracts, dict):
        return functions
    for qualified, body in sorted(contracts.items()):
        if not isinstance(body, dict):
            continue
        abi = body.get("abi") or []
        file_name = qualified.split(":", 1)[0]
        for item in abi:
            if not isinstance(item, dict) or item.get("type") != "function":
                continue
            name = str(item.get("name") or "fallback")
            mutability = str(item.get("stateMutability") or "")
            functions.append(
                {
                    "name": name,
                    "visibility": "external",
                    "payable": mutability == "payable",
                    "view": mutability in {"view", "pure"},
                    "locator": f"{file_name}:0",
                    "privileged": False,
                    "time_dependent": False,
                    "value_flow": mutability == "payable",
                    "external": True,
                }
            )
    return functions


def build_attack_surface(
    *,
    cluster_id: str = DEFAULT_CLUSTER_ID,
    run_id: str = DEFAULT_RUN_ID,
    created_at: str = PINNED,
    source_units: list[dict[str, Any]] | None = None,
    slither_json: dict[str, Any] | None = None,
    solc_json: dict[str, Any] | None = None,
    source_text: str | None = None,
    locator: str = "target/src/Contract.sol",
) -> dict[str, Any]:
    functions: list[dict[str, Any]] = []
    states: list[dict[str, Any]] = []
    if source_units:
        parsed = parse_sources(source_units)
        functions.extend(parsed["functions"])
        states.extend(parsed["state_variables"])
    elif source_text:
        parsed = parse_solidity(source_text, locator=locator)
        functions.extend(parsed["functions"])
        states.extend(parsed["state_variables"])
    if slither_json:
        functions.extend(_functions_from_slither(slither_json))
    if solc_json:
        functions.extend(_functions_from_solc(solc_json))
    unique_fns: dict[str, dict[str, Any]] = {}
    for item in functions:
        unique_fns[f"{item['name']}:{item['locator']}"] = item
    functions = [unique_fns[key] for key in sorted(unique_fns)]
    unique_state: dict[str, dict[str, Any]] = {str(item["name"]): item for item in states}
    states = [unique_state[key] for key in sorted(unique_state)]

    nodes = [
        function_node(
            run_id=run_id,
            created_at=created_at,
            name=str(item["name"]),
            visibility=str(item.get("visibility") or "public"),
            locator=str(item.get("locator") or locator),
            extra={
                "payable": bool(item.get("payable")),
                "view": bool(item.get("view")),
                "entry": item.get("visibility") in {"public", "external"},
            },
        )
        for item in functions
    ]
    nodes.extend(
        state_node(
            run_id=run_id,
            created_at=created_at,
            name=str(item["name"]),
            locator=str(item.get("locator") or locator),
        )
        for item in states
    )
    entry_points = [
        item for item in functions if item.get("visibility") in {"public", "external"}
    ]
    payload = json.dumps(
        {
            "cluster_id": cluster_id,
            "entry_points": [item["name"] for item in entry_points],
            "state_variables": [item["name"] for item in states],
            "function_count": len(functions),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    summary = map_summary_node(
        map_type="AttackSurfaceMap",
        cluster_id=cluster_id,
        run_id=run_id,
        created_at=created_at,
        payload=payload,
        extra={"entry_count": len(entry_points), "state_count": len(states)},
    )
    nodes.append(summary)
    return {
        "map_type": "attack_surface",
        "cluster_id": cluster_id,
        "nodes": nodes,
        "edges": [],
        "entry_points": entry_points,
        "state_variables": states,
        "functions": functions,
        "payload": json.loads(payload),
    }
