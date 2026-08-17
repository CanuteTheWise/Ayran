"""Static parsers for curated Markdown, YAML, JSON, and code-as-data. No execution."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ayran.graph.canonical import sha256_bytes
from ayran.knowledge.paths import MAX_RECORD_BYTES, PARSER_VERSION
from ayran.tools.yaml_lite import YamlLiteError, load_yaml

_CODE_SUFFIXES = {".sol", ".vy", ".rs", ".move", ".py", ".ts", ".js"}


@dataclass(slots=True)
class ParsedRecord:
    locator: str
    payload: dict[str, Any]
    raw_hash: str
    parser_version: str = PARSER_VERSION
    kind: str = "structured"


def _hash_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def _bounded(text: str, max_bytes: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def parse_yaml_mapping(text: str) -> dict[str, Any]:
    loaded = load_yaml(text)
    if not isinstance(loaded, dict):
        raise YamlLiteError("knowledge YAML must be a mapping")
    return loaded


def parse_markdown(text: str) -> dict[str, Any]:
    body = text.replace("\r\n", "\n").replace("\r", "\n")
    if body.startswith("---\n"):
        rest = body[4:]
        end = rest.find("\n---\n")
        if end >= 0:
            front = rest[:end]
            remainder = rest[end + 5 :]
            mapping = parse_yaml_mapping(front)
            mapping.setdefault("body", remainder.strip())
            return mapping
    return {"title": "", "body": body.strip(), "record_type": "method"}


def parse_json_mapping(text: str) -> dict[str, Any]:
    loaded = json.loads(text)
    if not isinstance(loaded, dict):
        raise ValueError("knowledge JSON must be an object")
    return loaded


def parse_code_as_data(text: str, path: str) -> dict[str, Any]:
    return {
        "record_type": "false_positive_trap" if "hard-negative" in path or "hard_negative" in path else "method",
        "title": Path(path).stem,
        "safe_variant_code": text,
        "body": text,
        "language": "solidity" if path.endswith(".sol") else None,
    }


def parse_file(path: Path, *, max_bytes: int = MAX_RECORD_BYTES, locator: str | None = None) -> ParsedRecord:
    raw = path.read_bytes()
    digest = sha256_bytes(raw)
    text = _bounded(raw.decode("utf-8"), max_bytes)
    suffix = path.suffix.lower()
    relative = locator or path.name
    if suffix in {".yaml", ".yml"}:
        payload = parse_yaml_mapping(text)
        kind = "yaml"
    elif suffix == ".json":
        payload = parse_json_mapping(text)
        kind = "json"
    elif suffix in {".md", ".markdown"}:
        payload = parse_markdown(text)
        kind = "markdown"
    elif suffix in _CODE_SUFFIXES:
        payload = parse_code_as_data(text, relative)
        kind = "code"
    else:
        payload = {"title": path.stem, "body": text, "record_type": "method"}
        kind = "text"
    payload.setdefault("canonical_key", path.stem)
    return ParsedRecord(locator=relative, payload=payload, raw_hash=digest, kind=kind)


def parse_tree(root: Path, *, max_bytes: int = MAX_RECORD_BYTES) -> list[ParsedRecord]:
    records: list[ParsedRecord] = []
    if not root.is_dir():
        return records
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name.startswith("."):
            continue
        records.append(
            parse_file(path, max_bytes=max_bytes, locator=path.relative_to(root).as_posix())
        )
    return records


@dataclass(slots=True)
class TreeSnapshot:
    files: list[dict[str, Any]] = field(default_factory=list)
    tree_hash: str = ""


def snapshot_tree(root: Path) -> TreeSnapshot:
    files: list[dict[str, Any]] = []
    if root.is_dir():
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            relative = path.relative_to(root).as_posix()
            payload = path.read_bytes()
            files.append(
                {
                    "path": relative,
                    "sha256": sha256_bytes(payload),
                    "size": len(payload),
                }
            )
    material = [{"path": item["path"], "sha256": item["sha256"]} for item in files]
    from ayran.graph.canonical import canonical_hash

    return TreeSnapshot(files=files, tree_hash=canonical_hash(material))
