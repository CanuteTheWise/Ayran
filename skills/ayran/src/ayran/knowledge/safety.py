"""Injection and safety scan for curated Global Graph records (blueprint §7.3)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ayran.router.injection import looks_like_injection

_ROLE_MARKERS = (
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"<<SYS>>", re.IGNORECASE),
    re.compile(r"</?system>", re.IGNORECASE),
    re.compile(r"^\s*system\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*assistant\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"<!--\s*SYSTEM\s*-->", re.IGNORECASE),
)
_TOOL_MARKUP = (
    re.compile(r"<tool_call\b", re.IGNORECASE),
    re.compile(r"```tool", re.IGNORECASE),
    re.compile(r"invoke[_ ]tool", re.IGNORECASE),
    re.compile(r"<function_call\b", re.IGNORECASE),
)
_HIDDEN_HTML = (
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"<script\b", re.IGNORECASE),
    re.compile(r"<iframe\b", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
)
_EXTERNAL_FETCH = (
    re.compile(r"!\[[^\]]*\]\(\s*https?://", re.IGNORECASE),
    re.compile(r"<img[^>]+src\s*=\s*['\"]https?://", re.IGNORECASE),
)
_POLICY_INSTRUCTIONS = (
    re.compile(r"ignore (all|previous|prior) instructions", re.IGNORECASE),
    re.compile(r"you are now", re.IGNORECASE),
    re.compile(r"override (the )?(policy|scope)", re.IGNORECASE),
    re.compile(r"disable (the )?(policy|gate|scope)", re.IGNORECASE),
    re.compile(r"grant (yourself )?(permission|access)", re.IGNORECASE),
    re.compile(r"change (the )?tool allowlist", re.IGNORECASE),
)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\ufeff\u2060]")
_URL = re.compile(r"https?://[^\s)>\"]+", re.IGNORECASE)
_COMMAND = re.compile(
    r"\b(curl|wget|npm install|pip install|foundryup|chmod \+x|eval\(|exec\()\b",
    re.IGNORECASE,
)
_PACKAGE = re.compile(r"\b(npm|pip|forge|cargo)\s+(install|add)\b", re.IGNORECASE)
_RPC = re.compile(r"\b(https?://[^\s]*rpc[^\s]*|wss://[^\s]+)\b", re.IGNORECASE)
_CREDENTIAL = re.compile(
    r"\b(?:api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"secret[_-]?key|private[_-]?key|password|passwd)\b\s*[:=]\s*\S+"
    r"|authorization:\s*bearer\s+\S+"
    r"|\b(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,})\b",
    re.IGNORECASE,
)
_UNSEPARABLE = (
    re.compile(r"run this (payload|exploit|shell)", re.IGNORECASE),
    re.compile(r"paste this into (bash|powershell|ipython)", re.IGNORECASE),
)


@dataclass(slots=True)
class SafetyResult:
    accepted: bool
    text: str
    metadata: dict[str, list[str]] = field(default_factory=dict)
    reason: str = ""
    stripped: list[str] = field(default_factory=list)


def _classify(text: str) -> dict[str, list[str]]:
    return {
        "urls": sorted({match.group(0) for match in _URL.finditer(text)}),
        "commands": sorted({match.group(0) for match in _COMMAND.finditer(text)}),
        "packages": sorted({match.group(0) for match in _PACKAGE.finditer(text)}),
        "rpc_endpoints": sorted({match.group(0) for match in _RPC.finditer(text)}),
        "credentials": sorted({match.group(0) for match in _CREDENTIAL.finditer(text)}),
    }


def strip_unsafe(text: str) -> tuple[str, list[str]]:
    stripped: list[str] = []
    cleaned = _ZERO_WIDTH.sub("", text)
    if cleaned != text:
        stripped.append("zero_width")
    without_controls = _CONTROL_CHARS.sub("", cleaned)
    if without_controls != cleaned:
        stripped.append("control_characters")
        cleaned = without_controls
    labeled: list[tuple[re.Pattern[str], str]] = [
        *[(item, "role_marker") for item in _ROLE_MARKERS],
        *[(item, "tool_markup") for item in _TOOL_MARKUP],
        *[(item, "hidden_html") for item in _HIDDEN_HTML],
        *[(item, "external_image") for item in _EXTERNAL_FETCH],
    ]
    for pattern, label in labeled:
        if pattern.search(cleaned):
            cleaned = pattern.sub(" ", cleaned)
            stripped.append(label)
    return cleaned, sorted(set(stripped))


def scan_text(text: str) -> SafetyResult:
    metadata = _classify(text)
    if any(pattern.search(text) for pattern in _UNSEPARABLE):
        return SafetyResult(
            accepted=False,
            text=text,
            metadata=metadata,
            reason="record cannot be separated from malicious instructions",
        )
    if metadata["credentials"]:
        return SafetyResult(
            accepted=False,
            text=text,
            metadata=metadata,
            reason="credential-shaped text is prohibited in knowledge records",
        )
    if looks_like_injection(text) or any(pattern.search(text) for pattern in _POLICY_INSTRUCTIONS):
        cleaned, stripped = strip_unsafe(text)
        if looks_like_injection(cleaned) or any(pattern.search(cleaned) for pattern in _POLICY_INSTRUCTIONS):
            return SafetyResult(
                accepted=False,
                text=cleaned,
                metadata=metadata,
                reason="untrusted instructions requesting policy/tool/scope changes",
                stripped=stripped,
            )
        return SafetyResult(accepted=True, text=cleaned, metadata=metadata, stripped=stripped)
    cleaned, stripped = strip_unsafe(text)
    return SafetyResult(accepted=True, text=cleaned, metadata=metadata, stripped=stripped)


def scan_mapping(payload: dict[str, Any]) -> SafetyResult:
    blobs: list[str] = []
    for key, value in payload.items():
        if key in {"urls", "origin", "source_uri", "locator"}:
            continue
        if isinstance(value, str):
            blobs.append(value)
        elif isinstance(value, list):
            blobs.extend(str(item) for item in value if isinstance(item, str))
    combined = "\n".join(blobs)
    return scan_text(combined)
