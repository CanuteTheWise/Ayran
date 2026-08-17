"""M8 CLI learning commands."""

from __future__ import annotations

from pathlib import Path

from ayran.learning.paths import PINNED_TIME
from ayran.learning.promote import promote_candidate
from m7_fixtures import invoke, payload
from m8_fixtures import CLAIM, graph_args, open_store, ready_candidate


def test_cli_learning_status_and_pipeline(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        args = graph_args(tmp_path, store)
        candidate = ready_candidate(store, claim=CLAIM)
        promote_candidate(
            candidate,
            store=store,
            learning_root=tmp_path / "learning",
            holdouts=[],
            created_at=PINNED_TIME,
        )
    finally:
        store.close()
    code, output = invoke(["learning", "status", *args])
    assert code == 0, output
    status = payload(output)
    assert status["ok"] is True
    assert status["result"]["routing_policy"]["policy_id"] != "m8-stub"
    code, output = invoke(["learning", "queue", *args])
    assert code == 0, output
    queued = payload(output)
    assert queued["ok"] is True
    code, output = invoke(["learning", "status", *args])
    assert code == 0, output
    body = payload(output)["result"]
    assert body["released_candidates"]
    code, output = invoke(["learning", "routing-policy", body["routing_policy"]["policy_id"], *args])
    assert code == 0, output
    policy = payload(output)["result"]
    assert policy["policy_id"] != "m8-stub"
