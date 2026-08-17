"""CLI/RPC surface for release build, validate, install, rollback, and uninstall."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ayran.release.bundle import build_bundle, validate_bundle
from ayran.release.install import install as apply_install
from ayran.release.install import plan_install, rollback, uninstall
from ayran.release.paths import RELEASE_VERSION, repository_root
from ayran.release.url_closure import build_complete_deps, write_complete_deps


def build(kind: str, *, destination: Path | str | None = None, root: Path | str | None = None) -> dict[str, Any]:
    return build_bundle(kind, destination=destination, root=root)


def validate(path: Path | str) -> dict[str, Any]:
    return validate_bundle(path)


def install_release(
    *,
    kind: str,
    prefix: Path,
    source: Path | None = None,
    prime: Path | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    src = source if source is not None else repository_root()
    if dry_run:
        return {**plan_install(kind=kind, prefix=prefix, prime=prime, dry_run=True), "applied": False}
    return apply_install(kind=kind, prefix=prefix, source=src, prime=prime, dry_run=False)


def rollback_release(receipt: Path) -> dict[str, Any]:
    return rollback(receipt)


def uninstall_release(receipt: Path) -> dict[str, Any]:
    return uninstall(receipt)


def closure(*, root: Path | str | None = None, write: bool = False) -> dict[str, Any]:
    if write:
        return write_complete_deps(root=root)
    return build_complete_deps(root)


def version() -> str:
    return RELEASE_VERSION
