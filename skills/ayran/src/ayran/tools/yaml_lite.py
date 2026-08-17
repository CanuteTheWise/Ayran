"""Restricted YAML 1.2 subset for capability manifests.

Ayran M4 adds zero runtime dependencies.  This loader/dumper understands the
block-style mappings, sequences, quoted strings, integers, booleans, and nulls
used by ``capabilities/*.yaml``.  It rejects anchors, tags, merge keys, and
nested flow collections.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

__all__ = ["YamlLiteError", "dump_yaml", "load_yaml"]


class YamlLiteError(ValueError):
    """The document is outside the supported YAML subset."""


def load_yaml(text: str) -> Any:
    """Parse one restricted YAML document into JSON-compatible Python values."""

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    index = 0
    n = len(lines)

    def _peek() -> tuple[int, str] | None:
        nonlocal index
        while index < n:
            raw = lines[index]
            stripped = raw.split("#", 1)[0].rstrip()
            if stripped.strip() == "":
                index += 1
                continue
            indent = len(stripped) - len(stripped.lstrip(" "))
            if "\t" in raw[:indent]:
                raise YamlLiteError("tabs are not allowed in indentation")
            return indent, stripped[indent:]
        return None

    def _parse_scalar(raw: str) -> Any:
        value = raw.strip()
        if value in {"[]"}:
            return []
        if value in {"{}",}:
            return {}
        if value in {"null", "Null", "NULL", "~"}:
            return None
        if value in {"true", "True"}:
            return True
        if value in {"false", "False"}:
            return False
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            quote = value[0]
            inner = value[1:-1]
            if quote == '"':
                return (
                    inner.replace("\\\\", "\\")
                    .replace("\\n", "\n")
                    .replace('\\"', '"')
                    .replace("\\t", "\t")
                )
            return inner
        if value.startswith("[") and value.endswith("]"):
            body = value[1:-1].strip()
            if not body:
                return []
            if "{" in body or "[" in body:
                raise YamlLiteError("nested flow collections are not supported")
            items: list[Any] = []
            for part in _split_flow(body):
                items.append(_parse_scalar(part))
            return items
        if value.startswith("{") and value.endswith("}"):
            raise YamlLiteError("flow mappings are not supported")
        if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
            return int(value)
        return value

    def _split_flow(body: str) -> list[str]:
        parts: list[str] = []
        buf: list[str] = []
        quote = ""
        for char in body:
            if quote:
                buf.append(char)
                if char == quote:
                    quote = ""
                continue
            if char in {'"', "'"}:
                quote = char
                buf.append(char)
                continue
            if char == ",":
                part = "".join(buf).strip()
                if part:
                    parts.append(part)
                buf = []
                continue
            buf.append(char)
        tail = "".join(buf).strip()
        if tail:
            parts.append(tail)
        return parts

    def _parse_block(min_indent: int) -> Any:
        nonlocal index
        peeked = _peek()
        if peeked is None:
            return None
        indent, content = peeked
        if indent < min_indent:
            return None
        if content.startswith("- "):
            return _parse_list(min_indent)
        return _parse_mapping(min_indent)

    def _parse_mapping(min_indent: int) -> dict[str, Any]:
        nonlocal index
        mapping: dict[str, Any] = {}
        while True:
            peeked = _peek()
            if peeked is None:
                break
            indent, content = peeked
            if indent < min_indent:
                break
            if indent > min_indent and min_indent > 0:
                break
            if content.startswith("- "):
                break
            if ":" not in content:
                raise YamlLiteError(f"expected mapping entry, got {content!r}")
            key, rest = content.split(":", 1)
            key = key.strip()
            if not key:
                raise YamlLiteError("empty mapping key")
            if key in mapping:
                raise YamlLiteError(f"duplicate key {key!r}")
            rest = rest.strip()
            index += 1
            if rest == "":
                nxt = _peek()
                if nxt is None or nxt[0] <= indent:
                    mapping[key] = None
                else:
                    mapping[key] = _parse_block(nxt[0])
            else:
                mapping[key] = _parse_scalar(rest)
        return mapping

    def _parse_list(min_indent: int) -> list[Any]:
        nonlocal index
        items: list[Any] = []
        while True:
            peeked = _peek()
            if peeked is None:
                break
            indent, content = peeked
            if indent < min_indent:
                break
            if not content.startswith("- "):
                break
            rest = content[2:]
            index += 1
            if rest == "":
                nxt = _peek()
                if nxt is None or nxt[0] <= indent:
                    items.append(None)
                else:
                    items.append(_parse_block(nxt[0]))
                continue
            if ":" in rest and not rest.strip().startswith(('"', "'")):
                # Inline mapping start: `- key: value`
                key, value = rest.split(":", 1)
                nested: dict[str, Any] = {key.strip(): _parse_scalar(value) if value.strip() else None}
                nxt = _peek()
                child_indent = indent + 2
                while nxt is not None and nxt[0] >= child_indent and not nxt[1].startswith("- "):
                    nested.update(_parse_mapping(child_indent))
                    nxt = _peek()
                items.append(nested)
            else:
                items.append(_parse_scalar(rest))
        return items

    document = _parse_block(0)
    leftover = _peek()
    if leftover is not None:
        raise YamlLiteError("multiple YAML documents or trailing content are not supported")
    return document


def dump_yaml(value: Any) -> str:
    """Serialize a JSON-compatible value to the restricted YAML subset."""

    lines: list[str] = []
    _emit(value, lines, 0)
    return "\n".join(lines) + "\n"


def _emit(value: Any, lines: list[str], indent: int) -> None:
    pad = " " * indent
    if isinstance(value, Mapping):
        if not value:
            lines.append(f"{pad}{{}}")
            return
        for key, item in value.items():
            _emit_entry(key, item, lines, indent, list_item=False)
        return
    if isinstance(value, list):
        if not value:
            lines.append(f"{pad}[]")
            return
        for item in value:
            if isinstance(item, Mapping):
                if not item:
                    lines.append(f"{pad}- {{}}")
                    continue
                first = True
                for key, sub in item.items():
                    _emit_entry(key, sub, lines, indent if first else indent + 2, list_item=first)
                    first = False
            elif isinstance(item, list):
                lines.append(f"{pad}-")
                _emit(item, lines, indent + 2)
            else:
                lines.append(f"{pad}- {_format_scalar(item)}")
        return
    lines.append(f"{pad}{_format_scalar(value)}")


def _emit_entry(key: Any, item: Any, lines: list[str], indent: int, *, list_item: bool) -> None:
    if not isinstance(key, str):
        raise YamlLiteError("mapping keys must be strings")
    pad = " " * indent
    heading = f"{pad}- {key}:" if list_item else f"{pad}{key}:"
    child_indent = indent + 2
    if isinstance(item, Mapping):
        if not item:
            lines.append(f"{heading} {{}}")
            return
        lines.append(heading)
        _emit(item, lines, child_indent)
        return
    if isinstance(item, list):
        if not item:
            lines.append(f"{heading} []")
            return
        lines.append(heading)
        _emit(item, lines, child_indent)
        return
    lines.append(f"{heading} {_format_scalar(item)}")


def _format_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        return _quote_string(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        raise YamlLiteError("nested sequences must be dumped as block lists")
    raise YamlLiteError(f"unsupported YAML value type {type(value).__name__}")


def _quote_string(value: str) -> str:
    special = (
        not value
        or value[0] in ":-#&*!|>%@`\"'{"
        or any(ch in value for ch in ":#{}[]&*!|>%@`\"'\n\t")
        or value in {"true", "false", "null", "True", "False", "Null", "~", "yes", "no"}
        or value.strip() != value
        or value.isdigit()
        or (value.startswith("-") and value[1:].isdigit())
    )
    if not special:
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
    return f'"{escaped}"'
