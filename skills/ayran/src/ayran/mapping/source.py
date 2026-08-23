"""Deterministic Solidity source extraction used when tool graphs are incomplete."""

from __future__ import annotations

import re
from typing import Any

FUNCTION_RE = re.compile(
    r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*([^;{]*)\{",
    re.MULTILINE,
)
CONSTRUCTOR_RE = re.compile(
    r"constructor\s*\(([^)]*)\)\s*([^;{]*)\{",
    re.MULTILINE,
)
RECEIVE_RE = re.compile(
    r"\breceive\s*\(\s*\)\s*([^;{]*)\{",
    re.MULTILINE,
)
FALLBACK_RE = re.compile(
    r"\bfallback\s*\(([^)]*)\)\s*([^;{]*)\{",
    re.MULTILINE,
)
MODIFIER_HEADER_RE = re.compile(
    r"modifier\s+([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*([^;{]*)\{",
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

_SKIP_STATE_NAMES = frozenset({"public", "private", "internal", "constant", "immutable", "override"})


def _skip_string(source: str, index: int) -> int:
    quote = source[index]
    index += 1
    length = len(source)
    while index < length:
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == quote:
            return index + 1
        index += 1
    return length


def _skip_line_comment(source: str, index: int) -> int:
    length = len(source)
    while index < length and source[index] not in "\n\r":
        index += 1
    return index


def _skip_block_comment(source: str, index: int) -> int:
    length = len(source)
    index += 2
    while index + 1 < length:
        if source[index] == "*" and source[index + 1] == "/":
            return index + 2
        index += 1
    return length


def extract_body(source: str, open_brace: int) -> tuple[str, int, bool]:
    """Balanced-brace body slice from ``open_brace`` (the ``{``). Never raises.

    String/comment aware enough for fixtures: braces inside quotes or comments
    do not desync the scan. Truncated input yields ``("", end, True)``.
    """

    index = open_brace + 1
    depth = 1
    length = len(source)
    while index < length and depth > 0:
        char = source[index]
        if char in {'"', "'"}:
            index = _skip_string(source, index)
            continue
        if char == "/" and index + 1 < length:
            nxt = source[index + 1]
            if nxt == "/":
                index = _skip_line_comment(source, index)
                continue
            if nxt == "*":
                index = _skip_block_comment(source, index)
                continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace + 1 : index], index + 1, False
        index += 1
    return "", length, True


def _inside_span(offset: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= offset < end for start, end in spans)


def _visibility(suffix: str, default: str) -> str:
    for token in ("external", "public", "internal", "private"):
        if re.search(rf"\b{token}\b", suffix):
            return token
    return default


def _function_record(
    *,
    source: str,
    name: str,
    args: str,
    suffix: str,
    match_start: int,
    open_brace: int,
    locator: str,
    visibility: str,
    payable: bool,
) -> tuple[dict[str, Any], int, bool]:
    body, end, truncated = extract_body(source, open_brace)
    line = source[:match_start].count("\n") + 1
    body_start_line = source[:open_brace].count("\n") + 1
    probe = f"{suffix}\n{body}" if body else source[match_start : match_start + 800]
    record: dict[str, Any] = {
        "name": name,
        "visibility": visibility,
        "payable": payable,
        "view": bool(re.search(r"\b(view|pure)\b", suffix)),
        "args": args.strip(),
        "locator": f"{locator}:{line}",
        "privileged": bool(AUTH_RE.search(suffix) or AUTH_RE.search(probe)),
        "time_dependent": bool(TIME_RE.search(probe)),
        "value_flow": bool(VALUE_RE.search(probe) or payable),
        "external": bool(EXT_RE.search(probe)),
        "body": body,
        "body_start_line": body_start_line,
    }
    if truncated:
        record["body_truncated"] = True
    return record, end, truncated


def parse_solidity(source: str, *, locator: str = "target/src/Contract.sol") -> dict[str, Any]:
    headers: list[tuple[int, str, re.Match[str]]] = []
    for match in FUNCTION_RE.finditer(source):
        headers.append((match.start(), "function", match))
    for match in CONSTRUCTOR_RE.finditer(source):
        headers.append((match.start(), "constructor", match))
    for match in RECEIVE_RE.finditer(source):
        headers.append((match.start(), "receive", match))
    for match in FALLBACK_RE.finditer(source):
        headers.append((match.start(), "fallback", match))
    for match in MODIFIER_HEADER_RE.finditer(source):
        headers.append((match.start(), "modifier", match))
    headers.sort(key=lambda item: (item[0], item[1]))

    functions: list[dict[str, Any]] = []
    body_spans: list[tuple[int, int]] = []
    for start, kind, match in headers:
        if _inside_span(start, body_spans):
            continue
        open_brace = match.end() - 1
        if kind == "function":
            suffix = match.group(3)
            record, end, truncated = _function_record(
                source=source,
                name=match.group(1),
                args=match.group(2),
                suffix=suffix,
                match_start=start,
                open_brace=open_brace,
                locator=locator,
                visibility=_visibility(suffix, "internal"),
                payable=bool(re.search(r"\bpayable\b", suffix)),
            )
            functions.append(record)
            body_spans.append((open_brace, len(source) if truncated else end))
        elif kind == "constructor":
            suffix = match.group(2)
            record, end, truncated = _function_record(
                source=source,
                name="constructor",
                args=match.group(1),
                suffix=suffix,
                match_start=start,
                open_brace=open_brace,
                locator=locator,
                visibility=_visibility(suffix, "internal"),
                payable=False,
            )
            functions.append(record)
            body_spans.append((open_brace, len(source) if truncated else end))
        elif kind == "receive":
            suffix = match.group(1)
            record, end, truncated = _function_record(
                source=source,
                name="receive",
                args="",
                suffix=suffix,
                match_start=start,
                open_brace=open_brace,
                locator=locator,
                visibility=_visibility(suffix, "external"),
                payable=True,
            )
            functions.append(record)
            body_spans.append((open_brace, len(source) if truncated else end))
        elif kind == "fallback":
            suffix = match.group(2)
            record, end, truncated = _function_record(
                source=source,
                name="fallback",
                args=match.group(1),
                suffix=suffix,
                match_start=start,
                open_brace=open_brace,
                locator=locator,
                visibility=_visibility(suffix, "external"),
                payable=bool(re.search(r"\bpayable\b", suffix)),
            )
            functions.append(record)
            body_spans.append((open_brace, len(source) if truncated else end))
        else:
            _body, end, truncated = extract_body(source, open_brace)
            body_spans.append((open_brace, len(source) if truncated else end))

    functions.sort(key=lambda row: (str(row["locator"]), str(row["name"])))
    states: list[dict[str, Any]] = []
    seen_state: set[str] = set()
    for match in STATE_RE.finditer(source):
        if _inside_span(match.start(), body_spans):
            continue
        name = match.group(1)
        if name in _SKIP_STATE_NAMES or name in seen_state:
            continue
        declared = match.group(0)
        seen_state.add(name)
        states.append(
            {
                "name": name,
                "locator": locator,
                "kind": "state",
                "constant": bool(re.search(r"\bconstant\b", declared)),
                "immutable": bool(re.search(r"\bimmutable\b", declared)),
            }
        )
    states.sort(key=lambda row: str(row["name"]))
    modifiers = [
        {"name": name, "locator": locator}
        for name in sorted(MODIFIER_RE.findall(source))
    ]
    contracts = [{"name": name, "locator": locator} for name in sorted(CONTRACT_RE.findall(source))]
    return {
        "contracts": contracts,
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
