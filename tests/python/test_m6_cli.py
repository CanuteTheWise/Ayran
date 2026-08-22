"""M6 CLI commands against a local unsafe graph root."""

from __future__ import annotations

import json
from pathlib import Path

from ayran.cli import main as cli_main
from m5_fixtures import VAULT_SOURCE, write_stream
from m6_fixtures import (
    open_store,
    promote_supported,
    seed_hypothesis,
)


def _invoke(argv: list[str]) -> tuple[int, str]:
    import io
    from contextlib import redirect_stdout

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli_main(argv)
    return code, buffer.getvalue()


def _graph_args(root: Path, stream: Path) -> list[str]:
    return ["--graph-root", str(root), "--stream", str(stream), "--allow-unsafe-filesystem"]


def test_cli_gate_a_forced_verdict_shape_rejected(tmp_path: Path) -> None:
    """R1: the CLI verdict channels are dead. The old forced shape fails closed
    with VERDICT_OVERRIDE_FORBIDDEN; a source-only analysis cannot reach a
    verdict because only credentialed challenger submissions enter Gate A."""

    store = open_store(tmp_path)
    try:
        fp = seed_hypothesis(
            store,
            claim="VulnerableVault.withdraw(uint256) sends eth to arbitrary user",
            attack_path=["withdraw"],
            root_cause="arbitrary-send-eth",
        )
        promote_supported(store, fp["hypothesis_id"])
        root, stream = write_stream(tmp_path, store)
    finally:
        store.close()
    code, output = _invoke(
        [
            "gate-a",
            fp["hypothesis_id"],
            *_graph_args(root, stream),
            "--analysis",
            json.dumps({"source": VAULT_SOURCE, "verdict": "poc_worthy"}),
        ]
    )
    assert code == 2, output
    assert "VERDICT_OVERRIDE_FORBIDDEN" in output
    code, output = _invoke(
        ["gate-a", fp["hypothesis_id"], *_graph_args(root, stream), "--analysis", json.dumps({"source": VAULT_SOURCE})]
    )
    assert code == 2, output
    assert "SUBMISSION_INVALID" in output
    code, trans = _invoke(
        [
            "evidence",
            "transition",
            fp["hypothesis_id"],
            "--to",
            "supported",
            "--evidence",
            json.dumps({"path": "x"}),
            *_graph_args(root, stream),
        ]
    )
    assert code == 2
    assert "MISSING_EVIDENCE" in trans or "TRANSITION" in trans or "accepted" in trans
