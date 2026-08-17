"""Graph-scoped M1 operator CLI.

The general runtime/service CLI is deliberately deferred to M2.  This module
only opens one explicit graph root and its immutable stream identity document.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from .canonical import canonical_bytes
from .errors import GraphError
from .recovery import GraphStore


def _stream(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("stream identity must be a JSON object")
    return cast(dict[str, Any], value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ayran", description="Ayran Graph Fabric operator tools")
    root = parser.add_subparsers(dest="scope", required=True)
    graph = root.add_parser("graph", help="operate on one M1 graph namespace")
    actions = graph.add_subparsers(dest="action", required=True)

    def action(name: str, help_text: str) -> argparse.ArgumentParser:
        command = actions.add_parser(name, help=help_text)
        command.add_argument("--root", type=Path, required=True, help="authoritative ext4 graph root")
        command.add_argument(
            "--stream", type=Path, required=True, help="immutable graph stream identity JSON"
        )
        command.add_argument(
            "--allow-unsafe-filesystem",
            action="store_true",
            help=argparse.SUPPRESS,
        )
        return command

    action("verify", "verify journal, manifests, projection, and cursor agreement")
    action("replay", "idempotently project committed journal batches")
    rebuild = action("rebuild", "build and validate a side-by-side projection")
    rebuild.add_argument(
        "--from",
        dest="source",
        default="zero",
        help="zero or a verified graph checkpoint path",
    )
    action("doctor", "produce a graph-scoped integrity report")
    checkpoint = action("checkpoint", "write a signed-by-hash graph checkpoint manifest")
    checkpoint.add_argument("--target-hash")
    checkpoint.add_argument("--config-hash")
    checkpoint.add_argument("--source-hash")
    checkpoint.add_argument("--tool-hash")
    checkpoint.add_argument("--artifact-manifest-hash")
    action("rollback-projection", "restore the preceding validated projection pointer")
    return parser


def _execute(arguments: argparse.Namespace) -> dict[str, Any]:
    stream = _stream(arguments.stream)
    with GraphStore(
        arguments.root,
        stream,
        allow_unsafe_filesystem=bool(arguments.allow_unsafe_filesystem),
    ) as store:
        if arguments.action == "verify":
            return store.verify()
        if arguments.action == "replay":
            return store.replay()
        if arguments.action == "rebuild":
            checkpoint = None if arguments.source == "zero" else Path(arguments.source)
            return store.rebuild(from_checkpoint=checkpoint)
        if arguments.action == "doctor":
            return store.doctor()
        if arguments.action == "checkpoint":
            return store.checkpoint(
                target_hash=arguments.target_hash,
                config_hash=arguments.config_hash,
                source_hash=arguments.source_hash,
                tool_hash=arguments.tool_hash,
                artifact_manifest_hash=arguments.artifact_manifest_hash,
            )
        if arguments.action == "rollback-projection":
            return store.rollback_projection()
    raise AssertionError("argparse accepted an unknown graph action")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    try:
        result = _execute(parser.parse_args(argv))
    except (GraphError, OSError, ValueError, json.JSONDecodeError) as error:
        if isinstance(error, GraphError):
            payload: dict[str, Any] = {"ok": False, "error": error.as_dict()}
        else:
            payload = {
                "ok": False,
                "error": {
                    "code": "CONTRACT_INVALID",
                    "message": str(error),
                    "retryable": False,
                },
            }
        sys.stderr.buffer.write(canonical_bytes(payload) + b"\n")
        return 2
    sys.stdout.buffer.write(canonical_bytes({"ok": True, "result": result}) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
