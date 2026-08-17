"""M9 CLI eval/release smoke tests."""

from __future__ import annotations

from pathlib import Path

from m7_fixtures import invoke, payload


def test_eval_run_full_sequence_offline(tmp_path: Path) -> None:
    code, output = invoke(
        ["eval", "run", "--seed", "7", "--results-root", str(tmp_path / "results")]
    )
    assert code == 0, output
    body = payload(output)["result"]
    assert body["gate"]["release_ready"] is True
    assert body["execution_mode"] == "sealed_fixture_offline"
    assert len(body["arms"]) == 8
