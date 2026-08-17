"""Sealed-set leakage scan: fixture IDs must be unreachable from Global/Learning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ayran.evaluation.errors import SEALED_LEAKAGE, EvaluationError
from ayran.evaluation.paths import repository_root
from ayran.evaluation.sealed import all_sealed_tokens, load_catalog
from ayran.graph.canonical import canonical_hash

_SKIP_PARTS = {
    "evals",
    "tests",
    "node_modules",
    ".venv",
    ".git",
    "dist",
    "var",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}


def _iter_text_files(root: Path) -> list[Path]:
    files: list[Path] = []
    if not root.is_dir():
        return files
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_PARTS for part in path.parts):
            continue
        if path.suffix.lower() not in {".json", ".yaml", ".yml", ".md", ".txt", ".py"}:
            continue
        files.append(path)
    return files


def scan_leakage(
    *,
    knowledge_root: Path | str | None = None,
    learning_root: Path | str | None = None,
    evals: Path | str | None = None,
    extra_roots: list[Path] | None = None,
) -> dict[str, Any]:
    tokens = all_sealed_tokens(str(evals) if evals else None)
    fixtures = load_catalog(evals)
    hits: list[dict[str, str]] = []
    roots: list[Path] = []
    repo = repository_root()
    if knowledge_root is not None:
        roots.append(Path(knowledge_root))
    else:
        roots.append(repo / "knowledge")
    if learning_root is not None:
        roots.append(Path(learning_root))
    else:
        roots.append(repo / "knowledge" / "learning")
    if extra_roots:
        roots.extend(extra_roots)
    for root in roots:
        if not root.exists():
            continue
        for path in _iter_text_files(root):
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            for token in tokens:
                if token and token in text:
                    hits.append({"path": str(path), "token": token})
    leaked = bool(hits)
    result = {
        "schema_version": "1.0.0",
        "clean": not leaked,
        "fixture_count": len(fixtures),
        "token_count": len(tokens),
        "hits": hits,
        "result_hash": "",
    }
    result["result_hash"] = canonical_hash({k: v for k, v in result.items() if k != "result_hash"})
    if leaked:
        raise EvaluationError(
            SEALED_LEAKAGE,
            "sealed evaluation fixtures leaked into Global or Learning corpus",
            details={"hits": hits[:20]},
        )
    return result


def corpus_fingerprint(knowledge_root: Path | str | None = None) -> str:
    root = Path(knowledge_root) if knowledge_root is not None else repository_root() / "knowledge"
    pointer = root / "current.json"
    if pointer.is_file():
        return canonical_hash(json.loads(pointer.read_text(encoding="utf-8")))
    registry = root / "registry"
    names = sorted(path.name for path in registry.glob("*.yaml")) if registry.is_dir() else []
    return canonical_hash({"registry": names, "pointer": None})
