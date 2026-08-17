"""Deterministic Layer and Complete release archives."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Any

from ayran.graph.canonical import canonical_hash
from ayran.release.errors import BUNDLE_INVALID, ReleaseError
from ayran.release.notices import build_notices
from ayran.release.paths import (
    RELEASE_VERSION,
    complete_archive_name,
    dist_root,
    layer_archive_name,
    repository_root,
)
from ayran.release.sbom import build_sbom
from ayran.release.signing import file_sha256, write_signature
from ayran.release.url_closure import write_complete_deps

_EXCLUDED = {
    ".git",
    ".venv",
    "node_modules",
    "dist",
    "var",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".hypothesis",
}

_SCRIPTS = (
    "packaging/linux/install-ayran.sh",
    "packaging/linux/uninstall-ayran.sh",
    "packaging/linux/verify-install.sh",
    "packaging/windows/install-ayran.ps1",
)


def _add_bytes(archive: tarfile.TarFile, name: str, payload: bytes, *, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name=name.replace("\\", "/"))
    info.size = len(payload)
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mode = mode
    archive.addfile(info, io.BytesIO(payload))


def _should_skip(relative: Path) -> bool:
    return any(part in _EXCLUDED for part in relative.parts)


def _payload_files(root: Path) -> list[tuple[str, Path]]:
    manifest = json.loads((root / "packaging" / "manifests" / "ayran-payload.json").read_text(encoding="utf-8"))
    selected: list[tuple[str, Path]] = []
    seen: set[str] = set()

    def add(path: Path, relative: str) -> None:
        key = relative.replace("\\", "/")
        if key in seen or not path.is_file() or path.is_symlink():
            return
        seen.add(key)
        selected.append((key, path))

    for value in manifest.get("files") or []:
        path = root / str(value)
        if path.is_file():
            add(path, str(value).replace("\\", "/"))
    for component in manifest.get("components") or []:
        rel = str(component.get("path") or "")
        base = root / rel
        if not base.exists():
            continue
        if base.is_file():
            add(base, rel.replace("\\", "/"))
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(root)
            if _should_skip(relative):
                continue
            add(path, relative.as_posix())
    for extra in _SCRIPTS:
        path = root / extra
        if path.is_file():
            add(path, extra)
    return sorted(selected, key=lambda item: item[0])


def _gzip_bytes(raw_tar: bytes) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0, compresslevel=9) as stream:
        stream.write(raw_tar)
    return buffer.getvalue()


def build_bundle(
    kind: str,
    *,
    destination: Path | str | None = None,
    root: Path | str | None = None,
    version: str = RELEASE_VERSION,
) -> dict[str, Any]:
    if kind not in {"layer", "complete"}:
        raise ReleaseError(BUNDLE_INVALID, f"unknown bundle kind {kind}")
    repo = Path(root) if root is not None else repository_root()
    out = Path(destination) if destination is not None else dist_root()
    out.mkdir(parents=True, exist_ok=True)
    closure = write_complete_deps(out / "manifests" / "complete-deps.json", root=repo)
    sbom = build_sbom(kind=f"ayran-{kind}", root=repo)
    notices = build_notices(kind=f"ayran-{kind}", root=repo)
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        for relative, path in _payload_files(repo):
            _add_bytes(archive, f"ayran/{relative}", path.read_bytes())
        _add_bytes(
            archive,
            "ayran/SBOM.json",
            (json.dumps(sbom, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        _add_bytes(archive, "ayran/THIRD-PARTY-NOTICES.md", notices.encode("utf-8"))
        _add_bytes(
            archive,
            "ayran/complete-deps.json",
            (json.dumps(closure, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        if kind == "complete":
            prime = repo / "vendor" / "cache" / "prime-agent-0.7.2.tgz"
            if prime.is_file():
                _add_bytes(archive, "ayran/vendor/cache/prime-agent-0.7.2.tgz", prime.read_bytes())
            install_sh = (repo / "packaging" / "linux" / "install-ayran.sh").read_bytes() if (
                repo / "packaging" / "linux" / "install-ayran.sh"
            ).is_file() else b"#!/bin/sh\npython -m ayran.cli release install --complete \"$@\"\n"
            _add_bytes(archive, "install-ayran.sh", install_sh, mode=0o755)
        else:
            install_sh = (repo / "packaging" / "linux" / "install-ayran.sh").read_bytes() if (
                repo / "packaging" / "linux" / "install-ayran.sh"
            ).is_file() else b"#!/bin/sh\npython -m ayran.cli release install --layer \"$@\"\n"
            _add_bytes(archive, "install-ayran.sh", install_sh, mode=0o755)
        for name, rel in (
            ("uninstall-ayran.sh", "packaging/linux/uninstall-ayran.sh"),
            ("verify-install.sh", "packaging/linux/verify-install.sh"),
            ("install-ayran.ps1", "packaging/windows/install-ayran.ps1"),
        ):
            path = repo / rel
            if path.is_file():
                mode = 0o755 if name.endswith(".sh") else 0o644
                _add_bytes(archive, name, path.read_bytes(), mode=mode)
    archive_name = layer_archive_name(version) if kind == "layer" else complete_archive_name(version)
    blob = _gzip_bytes(tar_buffer.getvalue())
    archive_path = out / archive_name
    archive_path.write_bytes(blob)
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    metadata = {
        "schema_version": "1.0.0",
        "kind": f"ayran-{kind}",
        "version": version,
        "archive": archive_name,
        "sha256": digest,
        "bytes": len(blob),
        "closure_hash": closure["content_hash"],
        "sbom_hash": sbom["content_hash"],
    }
    write_signature(out / f"{archive_name}.sig.json", metadata)
    (out / f"{archive_name}.sha256").write_text(digest + "\n", encoding="utf-8")
    (out / f"{archive_name}.sbom.json").write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / f"{archive_name}.THIRD-PARTY-NOTICES.md").write_text(notices, encoding="utf-8")
    metadata["content_hash"] = canonical_hash({k: v for k, v in metadata.items() if k != "content_hash"})
    return {**metadata, "path": str(archive_path)}


def validate_bundle(path: Path | str) -> dict[str, Any]:
    archive = Path(path)
    if not archive.is_file():
        raise ReleaseError(BUNDLE_INVALID, f"bundle not found: {archive}")
    digest = file_sha256(archive)
    sha_file = Path(str(archive) + ".sha256")
    if sha_file.is_file():
        recorded = sha_file.read_text(encoding="utf-8").strip()
        expected = digest.removeprefix("sha256:")
        if recorded not in {digest, expected} and not recorded.endswith(expected):
            raise ReleaseError(BUNDLE_INVALID, "bundle checksum does not match sidecar")
    with tarfile.open(archive, "r:gz") as handle:
        names = set(handle.getnames())
    required = {"install-ayran.sh", "ayran/SBOM.json", "ayran/THIRD-PARTY-NOTICES.md"}
    missing = sorted(required - names)
    if missing:
        raise ReleaseError(BUNDLE_INVALID, f"bundle missing required members: {missing}")
    return {"path": str(archive), "sha256": digest, "members": sorted(names), "ok": True}
