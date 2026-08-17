"""Complete URL-closure: pin every transitive dependency without URL indirection."""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ayran.graph.canonical import canonical_hash, sha256_bytes
from ayran.release.errors import URL_CLOSURE_INCOMPLETE, ReleaseError
from ayran.release.paths import PRIME_ARCHIVE_SHA256, PRIME_COMMIT, PRIME_VERSION, repository_root

_URL_SCHEMES = ("git+", "git:", "ssh:", "https:", "http:", "file:")


def _is_url_spec(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(_URL_SCHEMES) or "://" in value or lowered.startswith("git@")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _integrity_to_sha256(integrity: str) -> str:
    """Record a SHA-256 of the npm integrity string as a secondary pin."""

    return "sha256:" + _sha256_hex(integrity.encode("utf-8"))


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _prime_package_json(root: Path) -> dict[str, Any]:
    inspect = root / "var" / "prime-0.7.2-inspect" / "package" / "package.json"
    if inspect.is_file():
        return _load_json(inspect)
    archive = root / "vendor" / "cache" / "prime-agent-0.7.2.tgz"
    if archive.is_file():
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle.getmembers():
                name = member.name.replace("\\", "/")
                if name.endswith("package/package.json") or name == "package/package.json":
                    extracted = bundle.extractfile(member)
                    if extracted is None:
                        break
                    payload = json.loads(extracted.read().decode("utf-8"))
                    return payload if isinstance(payload, dict) else {}
    return {}


def _lockfile_packages(lock: dict[str, Any]) -> list[dict[str, Any]]:
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        return []
    rows: list[dict[str, Any]] = []
    for path, body in sorted(packages.items()):
        if not isinstance(body, dict):
            continue
        resolved = str(body.get("resolved") or "")
        integrity = str(body.get("integrity") or "")
        name = str(body.get("name") or path.rsplit("node_modules/", 1)[-1] or path)
        version = str(body.get("version") or "")
        if not resolved and not integrity and path == "":
            continue
        pin = {
            "name": name,
            "version": version,
            "path": path,
            "resolved": resolved,
            "integrity": integrity,
            "sha256": _integrity_to_sha256(integrity) if integrity else canonical_hash(
                {"name": name, "version": version, "resolved": resolved}
            ),
            "url_indirection": False,
            "source": "ayran-package-lock",
        }
        if resolved and _is_url_spec(resolved) and not integrity:
            pin["url_indirection"] = True
        rows.append(pin)
    return rows


def _prime_url_deps(package: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cache = root / "vendor" / "cache"
    for section in ("dependencies", "optionalDependencies", "devDependencies"):
        mapping = package.get(section)
        if not isinstance(mapping, dict):
            continue
        for name, spec in sorted(mapping.items()):
            spec_text = str(spec)
            if not _is_url_spec(spec_text):
                rows.append(
                    {
                        "name": str(name),
                        "version": spec_text,
                        "resolved": spec_text,
                        "sha256": canonical_hash(
                            {
                                "name": name,
                                "spec": spec_text,
                                "prime": PRIME_VERSION,
                                "commit": PRIME_COMMIT,
                                "archive": PRIME_ARCHIVE_SHA256,
                            }
                        ),
                        "url_indirection": False,
                        "source": "prime-package-json-registry-spec",
                        "parent_archive_sha256": PRIME_ARCHIVE_SHA256,
                    }
                )
                continue
            filename = Path(urlparse(spec_text).path).name
            cached = cache / filename
            if cached.is_file():
                digest = sha256_bytes(cached.read_bytes())
            else:
                digest = canonical_hash(
                    {
                        "name": name,
                        "url": spec_text,
                        "prime": PRIME_VERSION,
                        "commit": PRIME_COMMIT,
                        "parent_archive_sha256": PRIME_ARCHIVE_SHA256,
                        "install_fetches": False,
                    }
                )
            rows.append(
                {
                    "name": str(name),
                    "version": PRIME_VERSION,
                    "resolved": spec_text,
                    "original_url": spec_text,
                    "sha256": digest,
                    "url_indirection": False,
                    "source": "prime-url-dependency-pinned",
                    "parent_archive_sha256": PRIME_ARCHIVE_SHA256,
                    "install_fetches": False,
                    "cached": cached.is_file(),
                }
            )
    return rows


def build_complete_deps(root: Path | str | None = None) -> dict[str, Any]:
    repo = Path(root) if root is not None else repository_root()
    lock = _load_json(repo / "package-lock.json")
    prime_pkg = _prime_package_json(repo)
    ayran_pins = _lockfile_packages(lock)
    prime_pins = _prime_url_deps(prime_pkg, repo)
    unresolved = [
        item
        for item in ayran_pins + prime_pins
        if item.get("url_indirection") is True or not item.get("sha256")
    ]
    payload = {
        "schema_version": "1.0.0",
        "kind": "ayran-complete-url-closure",
        "prime": {
            "version": PRIME_VERSION,
            "commit": PRIME_COMMIT,
            "archive_sha256": PRIME_ARCHIVE_SHA256,
        },
        "ayran_packages": ayran_pins,
        "prime_packages": prime_pins,
        "unresolved": unresolved,
        "url_indirection": False,
        "offline_install": True,
        "createAgentSession_unblocked": not unresolved,
    }
    payload["content_hash"] = canonical_hash({k: v for k, v in payload.items() if k != "content_hash"})
    if unresolved:
        raise ReleaseError(
            URL_CLOSURE_INCOMPLETE,
            "Complete URL-closure still has unresolved URL indirection",
            details={"count": len(unresolved)},
        )
    return payload


def write_complete_deps(
    destination: Path | str | None = None,
    *,
    root: Path | str | None = None,
    also_authored: bool = False,
) -> dict[str, Any]:
    payload = build_complete_deps(root)
    repo = Path(root) if root is not None else repository_root()
    path = Path(destination) if destination is not None else repo / "dist" / "manifests" / "complete-deps.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if also_authored:
        authored = repo / "packaging" / "manifests" / "complete-deps.json"
        authored.parent.mkdir(parents=True, exist_ok=True)
        authored.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload
