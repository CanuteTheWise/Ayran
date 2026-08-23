"""Sanitization transforms and execution-artifact scans (spec 6.1, 6.5, 11.3).

Pure functions plus one registry loader. No network, no execution: archive
inspection reads the zip central directory through stdlib ``zipfile`` and
never extracts a byte. The darknavy transform strips instruction lines that
direct fetching a raw.githubusercontent.com VERSION file (the documented
DarkNavy curl-home bait); sanitizer transforms are recorded in provenance
via the ingestion stage (spec 6.5 mandates a recorded sanitizer list).
"""

from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path

from ayran.knowledge.paths import default_knowledge_root, registry_dir

MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_ZIP_EXPANSION = 100

HOSTILE_ARTIFACTS_FILENAME = "hostile-artifacts.sha256"

# Sanctioned exception (spec 12-R4 C/E3): this file must name the exact
# upstream host so the stripper pattern can match it byte-for-byte.
_DARKNAVY_FETCH_LINE = re.compile(
    r"(?:curl|wget|invoke-webrequest|fetch[^\n]{0,20}ing?)"
    r"[^\n]{0,200}(?:raw\.githubusercontent\.com|\bVERSION\b[^\n]{0,40}(?:file|\.txt|\.md))",
    re.IGNORECASE,
)
_AMP_COMMAND_LINE = re.compile(
    r"^\s*(?:[-*\u2022]|\d+[.)]\s+|//+|#+|\*)*\s*(?:[A-Za-z][\w ]{0,23}:\s*)?"
    r"(?:npm|pip\d?|forge|git|curl|wget|make|cd|sudo|foundryup|python\d?|node|yarn|"
    r"apt(?:-get)?|bash|sh|chmod|echo|export|docker|brew|cargo)\b",
    re.IGNORECASE,
)

_BINARY_MAGICS: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip archive magic"),
    (b"PK\x05\x06", "zip archive magic (empty)"),
    (b"\x1f\x8b", "gzip archive magic"),
    (b"BZh", "bzip2 archive magic"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive magic"),
    (b"Rar!", "rar archive magic"),
    (b"MZ", "PE executable magic"),
    (b"\x7fELF", "ELF executable magic"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable magic"),
    (b"\xce\xfa\xed\xfe", "Mach-O executable magic"),
    (b"\xfe\xed\xfa\xce", "Mach-O executable magic"),
    (b"\xfe\xed\xfa\xcf", "Mach-O executable magic"),
)
_ARCHIVE_EXTENSIONS = (".exe", ".dll", ".so", ".zip", ".tar.gz")
_INSTALLER_BAIT = (
    re.compile(r"\brun\s+[^\n]{0,60}\binstall(?:\.exe|\.sh|\.bat|\.ps1)?\b", re.IGNORECASE),
    re.compile(r"\binstall\.(?:exe|sh|bat|ps1)\b", re.IGNORECASE),
    re.compile(r"\bsetup\.exe\b", re.IGNORECASE),
)
_AUTO_FETCH = re.compile(
    r"(?:curl|wget|invoke-webrequest)[^\n]{0,200}https?://[^\s\"' ]*raw\.githubusercontent\.com",
    re.IGNORECASE,
)


def sanitize_darknavy_curl_strip(text: str) -> tuple[str, bool]:
    """Remove instruction lines that direct fetching version files.

    Bounded to lines that combine a fetch verb with the upstream raw host or
    a VERSION-file target; every byte outside the removed spans is preserved.
    """

    kept: list[str] = []
    changed = False
    for line in text.splitlines(keepends=True):
        if _DARKNAVY_FETCH_LINE.search(line):
            changed = True
            continue
        kept.append(line)
    return "".join(kept), changed


def _split_amp_chain(segment: str) -> list[str]:
    parts: list[str] = []
    buffer: list[str] = []
    quote = ""
    index = 0
    while index < len(segment):
        char = segment[index]
        if quote:
            buffer.append(char)
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            buffer.append(char)
            index += 1
            continue
        if char == "&" and segment[index : index + 2] == "&&":
            parts.append("".join(buffer))
            buffer = []
            index += 2
            continue
        buffer.append(char)
        index += 1
    parts.append("".join(buffer))
    return parts


def sanitize_shuvon_amp_rewrite(text: str) -> tuple[str, bool]:
    """Rewrite ``cmdA && cmdB`` shell chains into numbered single-purpose lines.

    Only instruction-shaped lines are rewritten (a command verb must lead the
    line and no open parenthesis may precede the first ``&&``), so Solidity
    expressions such as ``require(x && y)`` stay byte-identical.
    """

    output: list[str] = []
    changed = False
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        eol = line[len(body) :]
        if "&&" not in body or not _AMP_COMMAND_LINE.match(body):
            output.append(line)
            continue
        first_amp = body.index("&&")
        if "(" in body[:first_amp]:
            output.append(line)
            continue
        segments = [part.strip() for part in _split_amp_chain(body)]
        segments = [part for part in segments if part]
        if len(segments) < 2:
            output.append(line)
            continue
        changed = True
        output.extend(f"{number}. {segment}{eol}" for number, segment in enumerate(segments, 1))
    return "".join(output), changed


def _zip_expansion_reasons(data: bytes) -> list[str]:
    if not data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return []
    reasons: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
    except zipfile.BadZipFile:
        return ["zip central directory is unreadable"]
    if not infos:
        return []
    uncompressed = sum(info.file_size for info in infos)
    compressed = sum(max(info.compress_size, 1) for info in infos)
    if uncompressed / max(compressed, 1) > MAX_ZIP_EXPANSION:
        reasons.append(
            f"zip expansion ratio {uncompressed / max(compressed, 1):.1f}x exceeds "
            f"{MAX_ZIP_EXPANSION}x (central-directory sizes)"
        )
    if uncompressed / max(len(data), 1) > MAX_ZIP_EXPANSION:
        reasons.append(
            f"zip expansion ratio {uncompressed / max(len(data), 1):.1f}x versus archive bytes "
            f"exceeds {MAX_ZIP_EXPANSION}x"
        )
    return reasons


def scan_execution_artifacts(name: str, data: bytes) -> list[str]:
    """Flag binaries, archives, installer bait, auto-fetch bait, and size caps."""

    reasons: list[str] = []
    if len(data) > MAX_ARCHIVE_BYTES:
        reasons.append(f"artifact size {len(data)} exceeds MAX_ARCHIVE_BYTES {MAX_ARCHIVE_BYTES}")
    lowered = name.lower()
    for magic, label in _BINARY_MAGICS:
        if data.startswith(magic):
            reasons.append(f"binary payload: {label}")
    for extension in _ARCHIVE_EXTENSIONS:
        if lowered.endswith(extension):
            reasons.append(f"payload extension prohibited: {extension}")
    reasons.extend(_zip_expansion_reasons(data))
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return reasons
    for pattern in _INSTALLER_BAIT:
        found = pattern.search(text)
        if found is not None:
            reasons.append(f"installer bait: {found.group(0).strip()!r}")
            break
    fetch = _AUTO_FETCH.search(text)
    if fetch is not None:
        reasons.append(f"auto-fetch instruction: {fetch.group(0).strip()!r}")
    return reasons


def hostile_artifacts_path(knowledge_root: Path | None = None) -> Path:
    base = Path(knowledge_root) if knowledge_root is not None else default_knowledge_root()
    return registry_dir(base) / HOSTILE_ARTIFACTS_FILENAME


_SHA256_LINE = re.compile(r"^([0-9a-fA-F]{64})\s{1,}(\S.*)$")


def load_hostile_hashes(knowledge_root: Path | None = None) -> dict[str, str]:
    """Merge the deployment blocklist with the repository-seeded blocklist."""

    table: dict[str, str] = {}
    candidates: list[Path] = []
    if knowledge_root is not None:
        candidates.append(hostile_artifacts_path(knowledge_root))
    default_path = hostile_artifacts_path()
    if default_path not in candidates:
        candidates.append(default_path)
    for path in candidates:
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = _SHA256_LINE.match(line)
            if match is None:
                continue
            table.setdefault(match.group(1).lower(), match.group(2).strip())
    return table


def check_hostile_hash(digest_hex: str, table: dict[str, str] | None = None) -> str | None:
    """Return the block reason for a known-hostile artifact hash, else ``None``."""

    entries = table if table is not None else load_hostile_hashes()
    normalized = digest_hex.strip().lower().removeprefix("sha256:")
    label = entries.get(normalized)
    if label is None:
        return None
    return f"hostile artifact blocklist: {label}"
