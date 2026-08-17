"""THIRD-PARTY-NOTICES for bundled Python, npm, and Prime artifacts."""

from __future__ import annotations

from pathlib import Path

from ayran.release.paths import PRIME_COMMIT, PRIME_VERSION, repository_root

_PYTHON_LICENSES = {
    "jsonschema": "MIT",
    "pydantic": "MIT",
    "referencing": "MIT",
    "rfc8785": "Apache-2.0",
    "hatchling": "MIT",
}

_NPM_LICENSES = {
    "ajv": "MIT",
    "ajv-formats": "MIT",
    "canonicalize": "Apache-2.0",
}


def build_notices(*, kind: str, root: Path | str | None = None) -> str:
    repo = Path(root) if root is not None else repository_root()
    lines = [
        "# Third-party notices",
        "",
        "Ayran is a private project. This file records licenses for bundled inputs.",
        "",
        "## Python runtime packages",
        "",
    ]
    for name, spdx in sorted(_PYTHON_LICENSES.items()):
        lines.append(f"- `{name}`: {spdx}")
    lines.extend(["", "## npm packages", ""])
    for name, spdx in sorted(_NPM_LICENSES.items()):
        lines.append(f"- `{name}`: {spdx}")
    if kind == "ayran-complete":
        lines.extend(
            [
                "",
                "## Prime-Agent",
                "",
                f"Prime-Agent {PRIME_VERSION} commit `{PRIME_COMMIT}` is MIT-licensed.",
                "The pinned license text is `LICENSES/Prime-Agent-MIT.txt`.",
                "",
            ]
        )
    licenses = repo / "LICENSES" / "README.md"
    if licenses.is_file():
        lines.extend(["## Inventory", "", licenses.read_text(encoding="utf-8").strip(), ""])
    return "\n".join(lines) + "\n"
