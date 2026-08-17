#!/usr/bin/env python3
"""Plan, stage, and exactly clean the Ayran payload inside a selected WSL distro."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

ROOT_RECEIPT = ".ayran-stage-receipt.json"
ROOT_MARKER = ".ayran-stage-root"
STAGE_NAME = re.compile(r"^ayran-m[0-9]+-(layer|complete)-[0-9a-f]{16}$")
EXCLUDED_PARTS = {
    ".git",
    ".hypothesis",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".uv",
    ".venv",
    "__pycache__",
    "dist",
    "node_modules",
    "secrets",
    "var",
}
FORBIDDEN_SUFFIXES = {
    ".db",
    ".db-journal",
    ".journal",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
    ".sock",
    ".socket",
    ".sqlite",
    ".sqlite3",
}


class StageError(RuntimeError):
    """Fail-closed staging boundary error."""


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_relative(value: str) -> PurePosixPath:
    normalized = value.replace("\\", "/")
    raw_parts = normalized.split("/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise StageError(f"unsafe manifest path: {value!r}")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise StageError(f"manifest paths must already be normalized: {value!r}")
    return path


def reject_file(path: Path, relative: PurePosixPath) -> None:
    if path.is_symlink():
        raise StageError(f"symlinks are not allowed in staged inputs: {relative}")
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise StageError(f"only regular files may be staged: {relative}")
    lower = relative.name.lower()
    if (
        lower == ".env"
        or lower.startswith(".env.")
        or any(lower.endswith(item) for item in FORBIDDEN_SUFFIXES)
    ):
        raise StageError(f"runtime or secret material is forbidden: {relative}")
    if any(part.lower() in EXCLUDED_PARTS for part in relative.parts):
        raise StageError(f"excluded path reached payload enumeration: {relative}")


def add_tree(source: Path, relative: PurePosixPath, selected: dict[str, Path]) -> None:
    absolute = source.joinpath(*relative.parts)
    if absolute.is_symlink():
        raise StageError(f"symlink component is not allowed: {relative}")
    if not absolute.is_dir():
        raise StageError(f"payload component is missing or not a directory: {relative}")
    for current, directories, filenames in os.walk(absolute, followlinks=False):
        current_path = Path(current)
        kept: list[str] = []
        for name in sorted(directories):
            child = current_path / name
            child_relative = PurePosixPath(child.relative_to(source).as_posix())
            if name.lower() in EXCLUDED_PARTS:
                continue
            if child.is_symlink():
                raise StageError(f"symlink directory is not allowed: {child_relative}")
            kept.append(name)
        directories[:] = kept
        for name in sorted(filenames):
            path = current_path / name
            item = PurePosixPath(path.relative_to(source).as_posix())
            reject_file(path, item)
            selected[item.as_posix()] = path


def add_file(source: Path, value: str, selected: dict[str, Path]) -> None:
    relative = safe_relative(value)
    path = source.joinpath(*relative.parts)
    if not path.exists():
        raise StageError(f"payload file is missing: {relative}")
    reject_file(path, relative)
    selected[relative.as_posix()] = path


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise StageError(f"cannot read JSON manifest {path}: {error}") from error
    if not isinstance(value, dict):
        raise StageError(f"manifest must be an object: {path}")
    return value


def enumerate_payload(
    source: Path, distribution: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    manifest_path = source / "packaging/manifests/ayran-payload.json"
    payload = load_json(manifest_path)
    if (
        payload.get("schema_version") != "1.0.0"
        or payload.get("milestone") not in {"M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9"}
        or payload.get("runtime_implemented") is not True
    ):
        raise StageError("the staging helper only accepts a frozen M1-M9 payload contract")
    selected: dict[str, Path] = {}
    for value in payload.get("files", []):
        if not isinstance(value, str):
            raise StageError("payload files must be strings")
        add_file(source, value, selected)
    for component in payload.get("components", []):
        if not isinstance(component, dict) or not isinstance(component.get("path"), str):
            raise StageError("payload components must contain string paths")
        add_tree(source, safe_relative(component["path"]), selected)
    add_file(source, "packaging/manifests/ayran-payload.json", selected)
    add_file(source, "packaging/manifests/layer.json", selected)
    add_file(source, "packaging/manifests/complete.json", selected)
    add_file(source, "vendor/manifests/prime-v0.7.2.json", selected)
    if distribution == "complete":
        vendor = load_json(source / "vendor/manifests/prime-v0.7.2.json")
        artifact = vendor.get("artifact")
        if not isinstance(artifact, dict) or not isinstance(artifact.get("cache_path"), str):
            raise StageError("Complete vendor manifest has no cache path")
        add_file(source, artifact["cache_path"], selected)
        cached = source / artifact["cache_path"]
        actual = sha256_file(cached)
        if actual != artifact.get("sha256"):
            raise StageError("Complete Prime release archive does not match its pinned SHA-256")
    files = [
        {"path": relative, "sha256": sha256_file(path), "size": path.stat().st_size}
        for relative, path in sorted(selected.items())
    ]
    payload_identity = {
        "distribution": distribution,
        "files": files,
        "milestone": payload.get("milestone"),
        "payload_id": payload.get("payload_id"),
        "schema_version": "1.0.0",
    }
    return files, payload_identity


def ext4_mount(path: Path) -> dict[str, str]:
    probe = path.resolve(strict=False)
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    result = subprocess.run(
        ["findmnt", "--noheadings", "--output", "FSTYPE,SOURCE,TARGET", "--target", str(probe)],
        check=False,
        capture_output=True,
        text=True,
    )
    fields = result.stdout.strip().split(maxsplit=2)
    if result.returncode != 0 or len(fields) != 3:
        raise StageError(f"cannot resolve filesystem for staging base {path}")
    if fields[0] != "ext4":
        raise StageError(f"staging base must resolve to WSL ext4, found {fields[0]} at {fields[2]}")
    return {"filesystem": fields[0], "source": fields[1], "mount": fields[2]}


def build_plan(source: Path, distribution: str, base: Path) -> dict[str, Any]:
    if source.is_symlink():
        raise StageError("source root may not be a symlink")
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise StageError("source must be a real directory")
    mount = ext4_mount(base)
    files, identity = enumerate_payload(source, distribution)
    content_digest = hashlib.sha256(json_bytes(identity)).hexdigest()
    milestone = str(identity.get("milestone") or "m3").lower()
    stage_name = f"ayran-{milestone}-{distribution}-{content_digest[:16]}"
    return {
        "schema_version": "1.0.0",
        "action": "plan",
        "distribution": distribution,
        "source_root": str(source),
        "stage_base": str(base.resolve(strict=False)),
        "stage_root": str(base.resolve(strict=False) / stage_name),
        "stage_name": stage_name,
        "content_digest": content_digest,
        "file_count": len(files),
        "total_bytes": sum(item["size"] for item in files),
        "filesystem": mount,
        "files": files,
    }


def stage(source: Path, distribution: str, base: Path) -> dict[str, Any]:
    source = source.resolve(strict=True)
    plan = build_plan(source, distribution, base)
    base = Path(plan["stage_base"])
    target = Path(plan["stage_root"])
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    ext4_mount(base)
    if target.exists() or target.is_symlink():
        raise StageError(f"refusing to overwrite existing stage root: {target}")
    target.mkdir(mode=0o700)
    try:
        for item in plan["files"]:
            relative = safe_relative(item["path"])
            source_file = source.joinpath(*relative.parts)
            destination = target.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            shutil.copyfile(source_file, destination, follow_symlinks=False)
            destination.chmod(0o644)
            if (
                destination.stat().st_size != item["size"]
                or sha256_file(destination) != item["sha256"]
            ):
                raise StageError(f"post-copy integrity verification failed: {relative}")
        receipt = {
            "schema_version": "1.0.0",
            "receipt_type": "ayran-m9-stage",
            "distribution": distribution,
            "stage_name": plan["stage_name"],
            "content_digest": plan["content_digest"],
            "file_count": plan["file_count"],
            "total_bytes": plan["total_bytes"],
            "files": plan["files"],
            "ownership": "entire-stage-root-created-by-this-receipt",
        }
        receipt_bytes = json_bytes(receipt)
        (target / ROOT_RECEIPT).write_bytes(receipt_bytes)
        receipt_hash = hashlib.sha256(receipt_bytes).hexdigest()
        (target / ROOT_MARKER).write_text(receipt_hash + "\n", encoding="ascii")
        (target / ROOT_RECEIPT).chmod(0o600)
        (target / ROOT_MARKER).chmod(0o600)
    except BaseException:
        shutil.rmtree(target)
        raise
    return {
        "schema_version": "1.0.0",
        "action": "stage",
        "distribution": distribution,
        "stage_base": str(base),
        "stage_root": str(target),
        "content_digest": plan["content_digest"],
        "file_count": plan["file_count"],
        "total_bytes": plan["total_bytes"],
        "verified": True,
    }


def cleanup(stage_root: Path, base: Path) -> dict[str, Any]:
    if stage_root.is_symlink() or base.is_symlink():
        raise StageError("cleanup base and target may not be symlinks")
    base = base.resolve(strict=True)
    root = stage_root.resolve(strict=True)
    ext4_mount(base)
    if not root.is_dir() or root.parent != base or not STAGE_NAME.fullmatch(root.name):
        raise StageError(
            "cleanup target is not an exact Ayran stage child of the supplied staging base"
        )
    receipt_path = root / ROOT_RECEIPT
    marker_path = root / ROOT_MARKER
    if (
        receipt_path.is_symlink()
        or marker_path.is_symlink()
        or not receipt_path.is_file()
        or not marker_path.is_file()
    ):
        raise StageError("cleanup requires regular receipt and marker files")
    receipt_bytes = receipt_path.read_bytes()
    marker = marker_path.read_text(encoding="ascii").strip()
    if marker != hashlib.sha256(receipt_bytes).hexdigest():
        raise StageError("stage marker does not authenticate the receipt")
    receipt = load_json(receipt_path)
    if (
        receipt.get("receipt_type") not in {"ayran-m1-stage", "ayran-m3-stage", "ayran-m4-stage", "ayran-m5-stage", "ayran-m6-stage", "ayran-m7-stage", "ayran-m8-stage", "ayran-m9-stage"}
        or receipt.get("stage_name") != root.name
        or receipt.get("ownership") != "entire-stage-root-created-by-this-receipt"
    ):
        raise StageError("receipt does not authorize cleanup of this exact stage root")
    shutil.rmtree(root)
    return {
        "schema_version": "1.0.0",
        "action": "cleanup",
        "removed_stage_root": str(root),
        "removed": not root.exists(),
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    subcommands = value.add_subparsers(dest="action", required=True)
    for action in ("plan", "stage"):
        command = subcommands.add_parser(action)
        command.add_argument("--source", type=Path, required=True)
        command.add_argument("--distribution", choices=("layer", "complete"), required=True)
        command.add_argument(
            "--base", type=Path, default=Path.home() / ".local/state/ayran-m1-stage"
        )
    command = subcommands.add_parser("cleanup")
    command.add_argument("--stage-root", type=Path, required=True)
    command.add_argument("--base", type=Path, required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.action == "plan":
            result = build_plan(args.source, args.distribution, args.base)
        elif args.action == "stage":
            result = stage(args.source, args.distribution, args.base)
        else:
            result = cleanup(args.stage_root, args.base)
    except (OSError, StageError, subprocess.SubprocessError) as error:
        print(
            json.dumps(
                {"schema_version": "1.0.0", "action": args.action, "error": str(error)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    sys.stdout.buffer.write(json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
