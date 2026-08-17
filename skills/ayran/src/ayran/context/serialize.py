"""Injection-boundary serialization for bounded ContextPacks."""

from __future__ import annotations

from typing import Any

from ayran.context.ids import sha256_text

HEADER_MARK = "<!-- ayran-context-pack -->"
FOOTER_PREFIX = "<!-- checksum: "


def estimate_tokens(text: str) -> int:
    """Conservative upper bound: UTF-8 chars / 4."""

    return max(1, (len(text) + 3) // 4)


def estimate_section_tokens(title: str, content: str) -> int:
    return estimate_tokens(f"{title}\n{content}")


def serialize_injection(pack: dict[str, Any]) -> str:
    """Labeled body plus checksum footer. The extension prepends its own header."""

    lines = [HEADER_MARK, ""]
    for section in pack.get("sections") or []:
        classification = str(section.get("classification") or "UNTRUSTED_DATA")
        title = str(section.get("title") or "untitled")
        content = str(section.get("content") or "")
        lines.append(f"## [{classification}] {title}")
        lines.append("")
        lines.append(content)
        lines.append("")
    body = "\n".join(lines).rstrip() + "\n"
    digest = pack.get("integrity", {}).get("content_hash") or sha256_text(body)
    return f"{body}{FOOTER_PREFIX}{digest} -->\n"


def parse_checksum_footer(text: str) -> str | None:
    marker = FOOTER_PREFIX
    if marker not in text:
        return None
    tail = text.rsplit(marker, 1)[-1]
    value = tail.split("-->", 1)[0].strip()
    return value if value.startswith("sha256:") else None
