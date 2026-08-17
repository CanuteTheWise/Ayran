"""Release version pins and artifact locations."""

from __future__ import annotations

from pathlib import Path

RELEASE_VERSION = "0.1.6"
PAYLOAD_ID = "ayran-release-0.1.6"
PINNED_TIME = "2026-08-15T00:00:00Z"
PRIME_VERSION = "0.7.2"
PRIME_COMMIT = "83a0f9f9566219551fcb6ffaf7f519a815749a58"
PRIME_ARCHIVE_SHA256 = "bc5471f2a626d727b88a45eb745fff93b10c554a3c4fc5912f25d8c64b987f5e"


def repository_root() -> Path:
    return Path(__file__).resolve().parents[5]


def dist_root(override: Path | str | None = None) -> Path:
    if override is not None:
        return Path(override)
    return repository_root() / "dist"


def layer_archive_name(version: str = RELEASE_VERSION) -> str:
    return f"ayran-layer-{version}.tar.gz"


def complete_archive_name(version: str = RELEASE_VERSION) -> str:
    return f"ayran-complete-{version}.tar.gz"
