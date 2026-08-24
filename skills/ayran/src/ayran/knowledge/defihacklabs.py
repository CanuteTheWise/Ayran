"""DeFiHackLabs exploit-header parser (spec sections 6.3, 11.3, 12-R4 A).

Regex/stdlib text processing only. Ingested Solidity is NEVER compiled or
executed (spec 11.3 rule 6): this module reads source text as data and
nothing here invokes toolchains. Numeric assertion lines are captured
verbatim (never rounded, never reformatted) because they are execution
ground truth for Gate B obligations.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ayran.context.ids import content_id
from ayran.knowledge.models import IncidentCard, LicenseInfo, SourcePin, SourceRef
from ayran.knowledge.paths import PINNED_TIME

DEFIHACKLABS_ORIGIN = "https://github.com/SunWeb3Sec/DeFiHackLabs"
DEFIHACKLABS_PARSER_VERSION = "defihacklabs-1.1.0"

_HEX40 = r"0x[0-9a-fA-F]{40}(?![0-9a-fA-F])"
_TX_VALUE = r"0x(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40})(?![0-9a-fA-F])"
_RELPATH_RE = re.compile(r"^src/test/(\d{4}-\d{2})/([^/]+)\.sol$")
_EXPLOIT_BLOCK_RE = re.compile(r"EXPLOIT_BLOCK\s*(?:=|:)\s*(\d+)")
_EXPLOIT_BLOCK_LABEL_RE = re.compile(r"\bblock\s*[:=]\s*(\d+)", re.IGNORECASE)
_TX_HASH_RE = re.compile(
    rf"(?:tx|transaction)\D{{0,40}}({_TX_VALUE})",
    re.IGNORECASE,
)
_TX_ANY_RE = re.compile(_TX_VALUE, re.IGNORECASE)
_ADDRESS_LABEL_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "attacker",
        re.compile(
            rf"(?:attacker|exploiter|attacker\s+eoa|attacker\s+wallet|attack\s+eoa)\D{{0,40}}({_HEX40})",
            re.IGNORECASE,
        ),
    ),
    (
        "victim",
        re.compile(
            rf"(?:victim|harness|target\s+contract|vulnerable\s+contract|victim\s+contract|harness\s+contract|vulnerable)\D{{0,40}}({_HEX40})",
            re.IGNORECASE,
        ),
    ),
)
_VM_LABEL_RE = re.compile(
    rf'vm\.label\(\s*({_HEX40})\s*,\s*"([^"]*)"',
    re.IGNORECASE,
)
_VM_LABEL_ATTACKER_WORDS = ("attacker", "exploiter", "attack eoa")
_VM_LABEL_VICTIM_WORDS = ("victim", "harness", "target", "vulnerable")
_LOSS_RE = re.compile(
    r"(?:loss|lost|stolen|profit|amount)\s*[:=]?\s*[~$€£]*\s*([0-9][0-9 ,_.]*)\s*([A-Za-z$][A-Za-z]{0,10})?",
    re.IGNORECASE,
)
_ROOT_CAUSE_LABEL_RE = re.compile(
    r"^\s*(?:[-*>*#!]*\s*)?(?:root\s*cause|analysis|overview|description|details|exploit\s+summary)\s*[:\-]?\s*(.*)$",
    re.IGNORECASE,
)
_ASSERTION_RE = re.compile(
    r"^\s*(?:vm\.)?assert\w*\s*\(.*\d.*\)\s*;|^\s*require\w*\s*\(.*\d.*\)\s*;",
)
_MECHANISM_KEYWORDS = (
    "reentrancy",
    "oracle",
    "flash loan",
    "price manipulation",
    "access control",
    "arbitrary call",
    "signature",
    "approval",
    "inflation",
    "donation",
    "governance",
    "bridge",
    "cross-chain",
    "logic error",
    "rounding",
)


@dataclass(slots=True)
class DeFiHackLabsCard:
    """Fields extracted from one ``src/test/<YYYY-MM>/<Protocol>_exp.sol`` file."""

    relpath: str
    protocol: str
    incident: str
    month: str
    title: str
    tx_hash: str | None = None
    exploit_block: int | None = None
    attacker_address: str | None = None
    victim_addresses: list[str] = field(default_factory=list)
    loss_amount: str | None = None
    root_cause_lines: list[str] = field(default_factory=list)
    assertions: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Irregular:
    """A file that does not follow the documented layout, with the reason."""

    relpath: str
    reason: str


@dataclass(slots=True)
class ExploitFile:
    """One ``*_exp.sol`` candidate: parsed card or an irregular marker."""

    path: Path
    relpath: str
    card: DeFiHackLabsCard | None = None
    reason: str | None = None


def normalize_name(value: str) -> str:
    """Spec 6.3 normalization: lowercase, then strip every non-alphanumeric."""

    return re.sub(r"[^a-z0-9]", "", value.lower())


def contamination_group(protocol: str, incident: str) -> str:
    """Contamination group key ``contamination:<protocol>:<incident>`` (spec 6.3)."""

    return f"contamination:{normalize_name(protocol)}:{normalize_name(incident)}"


def _header_comment_lines(text: str) -> list[str]:
    """Card-header comment lines of the file.

    Real DeFiHackLabs files open with an SPDX comment, a ``pragma`` and
    ``import`` lines BEFORE the ``@KeyInfo`` card block, so those boilerplate
    lines no longer end the scan; collection stops at the first genuine
    Solidity declaration instead. Files whose comments lead directly (the
    documented fixture shape) parse exactly as before.
    """

    lines: list[str] = []
    in_block = False
    for raw in text.replace("\r\n", "\n").split("\n"):
        stripped = raw.strip()
        if in_block:
            lines.append(raw)
            if "*/" in stripped:
                in_block = False
            continue
        if stripped.startswith("/*"):
            lines.append(raw)
            in_block = "*/" not in stripped
            continue
        if stripped.startswith("//"):
            lines.append(raw)
            continue
        if stripped == "":
            continue
        if re.match(r"^(?:pragma\s+solidity|import\b)", stripped):
            continue
        break
    return lines


def _strip_comment_marks(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith("//"):
        return stripped[2:].strip()
    if stripped.startswith("/*"):
        stripped = stripped[2:]
    if stripped.endswith("*/"):
        stripped = stripped[:-2]
    if stripped.startswith("*"):
        stripped = stripped[1:]
    return stripped.strip()


def _root_cause(header: list[str]) -> list[str]:
    prose: list[str] = []
    collecting = False
    for line in header:
        clean = _strip_comment_marks(line)
        if not clean:
            if collecting:
                break
            continue
        match = _ROOT_CAUSE_LABEL_RE.match(clean)
        if match is not None:
            collecting = True
            head = match.group(1).strip()
            if head:
                prose.append(head)
            continue
        if collecting:
            if _TX_HASH_RE.search(clean) or re.match(r"^[\w ]{0,24}:", clean, re.IGNORECASE):
                break
            prose.append(clean)
    return prose


def _mechanism_keyword(root_cause_lines: list[str]) -> str | None:
    joined = " ".join(root_cause_lines).lower()
    for keyword in _MECHANISM_KEYWORDS:
        if keyword in joined:
            return keyword
    return None


def _title(card_protocol: str, root_cause_lines: list[str], incident: str) -> str:
    if root_cause_lines:
        head = re.sub(r"\s+", " ", root_cause_lines[0]).strip()
        if len(head) > 80:
            head = head[:77].rstrip() + "..."
        return f"{card_protocol} {head}"
    return f"{card_protocol} {incident}"


def parse_header(source_text: str, relpath: str) -> DeFiHackLabsCard | Irregular:
    """Parse one exploit file into a card, or report why the layout is irregular."""

    match = _RELPATH_RE.match(relpath)
    if match is None:
        if not relpath.startswith("src/test/"):
            return Irregular(relpath=relpath, reason="not under src/test/<YYYY-MM>/")
        return Irregular(
            relpath=relpath,
            reason="path does not match src/test/<YYYY-MM>/<name>_exp.sol",
        )
    month, filename = match.group(1), match.group(2)
    month_value = int(month[5:7])
    if not 1 <= month_value <= 12:
        return Irregular(relpath=relpath, reason=f"invalid month directory {month}")
    if not filename.endswith("_exp") or filename == "_exp":
        return Irregular(
            relpath=relpath,
            reason="filename lacks the documented _exp.sol suffix",
        )
    incident = filename[: -len("_exp")]
    protocol = incident.split("_", 1)[0]

    header = [_strip_comment_marks(line) for line in _header_comment_lines(source_text)]
    body_lines = [
        line.strip()
        for line in source_text.replace("\r\n", "\n").split("\n")
    ]

    tx_hash: str | None = None
    for clean in header:
        found = _TX_HASH_RE.search(clean)
        if found is not None:
            tx_hash = found.group(1)
            break
    if tx_hash is None:
        for clean in header:
            candidate = _TX_ANY_RE.search(clean)
            if candidate is not None and "tx" in clean.lower():
                tx_hash = candidate.group(0)
                break

    exploit_block: int | None = None
    block_match = _EXPLOIT_BLOCK_RE.search(source_text)
    if block_match is not None:
        exploit_block = int(block_match.group(1))
    else:
        label_match = _EXPLOIT_BLOCK_LABEL_RE.search(" ".join(header))
        if label_match is not None:
            exploit_block = int(label_match.group(1))

    attacker_address: str | None = None
    victim_addresses: list[str] = []
    attacker_pattern = dict(_ADDRESS_LABEL_RES)["attacker"]
    victim_pattern = dict(_ADDRESS_LABEL_RES)["victim"]
    for clean in header:
        if attacker_address is None:
            found = attacker_pattern.search(clean)
            if found is not None:
                attacker_address = found.group(1)
                continue
        found = victim_pattern.search(clean)
        if found is not None:
            victim_addresses.append(found.group(1))
    for labeled, name in _VM_LABEL_RE.findall(source_text):
        lowered = name.lower()
        if attacker_address is None and any(word in lowered for word in _VM_LABEL_ATTACKER_WORDS):
            attacker_address = labeled
        elif any(word in lowered for word in _VM_LABEL_VICTIM_WORDS):
            victim_addresses.append(labeled)
    victim_addresses = list(dict.fromkeys(victim_addresses))

    loss_amount: str | None = None
    for clean in header:
        found = _LOSS_RE.search(clean)
        if found is None:
            continue
        amount = re.sub(r"\s+", "_", found.group(1).strip().rstrip(",_.").lstrip())
        if not amount:
            continue
        token = (found.group(2) or "").strip()
        loss_amount = f"{amount} {token}" if token else amount
        break

    root_cause_lines = _root_cause(header)
    assertions = [line for line in body_lines if _ASSERTION_RE.match(line)]

    return DeFiHackLabsCard(
        relpath=relpath,
        protocol=protocol,
        incident=incident,
        month=month,
        title=_title(protocol, root_cause_lines, incident),
        tx_hash=tx_hash,
        exploit_block=exploit_block,
        attacker_address=attacker_address,
        victim_addresses=victim_addresses,
        loss_amount=loss_amount,
        root_cause_lines=root_cause_lines,
        assertions=assertions,
    )


def iter_exploit_files(root: Path, *, max_bytes: int = 1_048_576) -> Iterator[ExploitFile]:
    """Yield ``*_exp.sol`` candidates under ``src/test/**`` (Academy dirs skipped).

    Irregular files are yielded with reasons; nothing raises.
    """

    base = root / "src" / "test"
    if not base.is_dir():
        return
    for path in sorted(base.rglob("*.sol")):
        relpath = path.relative_to(root).as_posix()
        if "/Academy/" in f"/{relpath}":
            continue
        try:
            text = path.read_bytes()[:max_bytes].decode("utf-8")
        except (OSError, UnicodeDecodeError) as error:
            yield ExploitFile(path=path, relpath=relpath, reason=f"unreadable: {error}")
            continue
        parsed = parse_header(text, relpath)
        if isinstance(parsed, Irregular):
            yield ExploitFile(path=path, relpath=relpath, reason=parsed.reason)
            continue
        yield ExploitFile(path=path, relpath=relpath, card=parsed)


def provenance_uri(commit: str, relpath: str) -> str:
    """Upstream blob URI for one exploit file at the pinned commit."""

    return f"{DEFIHACKLABS_ORIGIN}/blob/{commit}/{relpath}"


def incident_values(card: DeFiHackLabsCard, *, commit: str) -> dict[str, Any]:
    """Model-field mapping shared by the payload path and ``to_incident_card``."""

    group = contamination_group(card.protocol, card.incident)
    summary = " ".join(line.strip() for line in card.root_cause_lines if line.strip())
    if not summary:
        summary = f"Reconstructed incident card for {card.incident}; no root-cause prose in header."
    attack_steps = [
        f"attacker EOA: {card.attacker_address}" if card.attacker_address else "",
        *(f"victim/harness contract: {address}" for address in card.victim_addresses),
    ]
    return {
        "record_type": "incident",
        "canonical_key": f"defihacklabs-{normalize_name(card.protocol)}-{normalize_name(card.incident)}-{normalize_name(card.month)}",
        "title": card.title,
        "summary": summary,
        "protocol": card.protocol,
        "component": None,
        "mechanism": _mechanism_keyword(card.root_cause_lines),
        "language": "solidity",
        "root_cause": summary,
        "attack_tx_hash": card.tx_hash,
        "attacker_address": card.attacker_address,
        "exploit_block": card.exploit_block,
        "loss_amount": card.loss_amount,
        "assertions_verbatim": list(card.assertions),
        "contamination_group": group,
        "benchmark_exposure": [group],
        "attack_steps": [step for step in attack_steps if step],
        "impact": card.loss_amount,
        "affected_protocols": [card.protocol],
        "urls": [provenance_uri(commit, card.relpath)] if commit else [],
        "safe_for_execution": False,
        "safe_for_retrieval": True,
        "parser_version": DEFIHACKLABS_PARSER_VERSION,
    }


def incident_payload(card: DeFiHackLabsCard, *, commit: str) -> dict[str, Any]:
    """Pipeline payload for one card (provenance stamped by the normalize stage)."""

    return incident_values(card, commit=commit)


def to_incident_card(
    card: DeFiHackLabsCard,
    *,
    source_ref: SourceRef,
    pin: SourcePin,
    raw_sha256: str,
    provenance_uri: str,
    sanitizers: list[str],
) -> IncidentCard:
    """Build a standalone ``IncidentCard`` with explicit provenance."""

    values = incident_values(card, commit=pin.commit or source_ref.commit_or_version)
    slug = str(values["canonical_key"])
    merged_pin = pin if (pin.commit and not source_ref.pin.commit) else source_ref.pin
    merged_ref = source_ref.model_copy(update={"pin": merged_pin})
    if provenance_uri and provenance_uri not in values["urls"]:
        values["urls"] = [*values["urls"], provenance_uri]
    return IncidentCard(
        record_id=content_id("krec", merged_ref.source_id, slug, raw_sha256),
        source_ref=merged_ref,
        commit_or_version=merged_ref.commit_or_version,
        date=datetime.fromisoformat(PINNED_TIME.replace("Z", "+00:00")),
        raw_hash=raw_sha256,
        license_info=LicenseInfo(spdx_id="Apache-2.0"),
        sanitizers=list(sanitizers),
        **values,
    )
