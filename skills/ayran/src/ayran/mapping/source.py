"""Deterministic Solidity source extraction used when tool graphs are incomplete."""

from __future__ import annotations

import re
from typing import Any

FUNCTION_RE = re.compile(
    r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*([^;{]*)\{",
    re.MULTILINE,
)
STATE_RE = re.compile(
    r"(?:mapping\s*\([^;]+\)|address|u?int\d*|bool|bytes\d*|string|bytes)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_]\w*)\s*(?:=|;)",
)
MODIFIER_RE = re.compile(r"modifier\s+([A-Za-z_]\w*)")
CONTRACT_RE = re.compile(r"contract\s+([A-Za-z_]\w*)")
TIME_RE = re.compile(r"\b(block\.timestamp|block\.number|cooldown|deadline|epoch|period|unlock)\b")
VALUE_RE = re.compile(r"\b(msg\.value|\.transfer\(|\.send\(|call\{value|safeTransfer|balances)\b")
AUTH_RE = re.compile(r"\b(onlyOwner|onlyRole|msg\.sender\s*==\s*owner|Ownable|AccessControl)\b")
EXT_RE = re.compile(r"\b(delegatecall|staticcall|\.call\{|interface |IOracle|IERC20)\b")


def parse_solidity(source: str, *, locator: str = "target/src/Contract.sol") -> dict[str, Any]:
    contracts = CONTRACT_RE.findall(source)
    functions: list[dict[str, Any]] = []
    for match in FUNCTION_RE.finditer(source):
        name = match.group(1)
        args = match.group(2)
        suffix = match.group(3)
        visibility = "internal"
        for token in ("external", "public", "internal", "private"):
            if re.search(rf"\b{token}\b", suffix):
                visibility = token
                break
        payable = bool(re.search(r"\bpayable\b", suffix))
        view = bool(re.search(r"\b(view|pure)\b", suffix))
        line = source[: match.start()].count("\n") + 1
        functions.append(
            {
                "name": name,
                "visibility": visibility,
                "payable": payable,
                "view": view,
                "args": args.strip(),
                "locator": f"{locator}:{line}",
                "privileged": bool(AUTH_RE.search(suffix) or AUTH_RE.search(source[match.start() : match.start() + 400])),
                "time_dependent": bool(TIME_RE.search(source[match.start() : match.start() + 800])),
                "value_flow": bool(VALUE_RE.search(source[match.start() : match.start() + 800]) or payable),
                "external": bool(EXT_RE.search(source[match.start() : match.start() + 800])),
            }
        )
    states = [
        {"name": name, "locator": locator, "kind": "state"}
        for name in STATE_RE.findall(source)
        if name not in {"public", "private", "internal"}
    ]
    modifiers = [{"name": name, "locator": locator} for name in MODIFIER_RE.findall(source)]
    return {
        "contracts": [{"name": name, "locator": locator} for name in contracts],
        "functions": functions,
        "state_variables": states,
        "modifiers": modifiers,
        "has_auth": bool(AUTH_RE.search(source)),
        "has_time": bool(TIME_RE.search(source)),
        "has_value": bool(VALUE_RE.search(source)),
        "has_external": bool(EXT_RE.search(source)),
        "locator": locator,
        "source": source,
    }


def parse_sources(units: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "contracts": [],
        "functions": [],
        "state_variables": [],
        "modifiers": [],
        "has_auth": False,
        "has_time": False,
        "has_value": False,
        "has_external": False,
        "units": [],
    }
    for unit in sorted(units, key=lambda row: str(row.get("locator") or row.get("path") or "")):
        source = str(unit.get("source") or "")
        locator = str(unit.get("locator") or unit.get("path") or "target/src/Contract.sol")
        parsed = parse_solidity(source, locator=locator)
        for key in ("contracts", "functions", "state_variables", "modifiers"):
            merged[key].extend(parsed[key])
        for flag in ("has_auth", "has_time", "has_value", "has_external"):
            merged[flag] = bool(merged[flag] or parsed[flag])
        merged["units"].append(parsed)
    return merged
