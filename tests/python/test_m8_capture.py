"""M8 outcome capture: M6 transitions, secret exclusion, shutdown capture."""

from __future__ import annotations

from pathlib import Path

from ayran.learning.capture import capture_outcome, capture_run_outcomes, redact_secrets
from ayran.learning.load import load_outcomes
from ayran.learning.paths import PINNED_TIME
from m5_fixtures import RUN_ID
from m6_fixtures import seed_hypothesis
from m8_fixtures import open_store


def test_redact_secrets_drops_keys_and_private_hex() -> None:
    payload = redact_secrets(
        {
            "claim": "reentrancy",
            "private_key": "0x" + "ab" * 32,
            "source_text": "pragma solidity ^0.8.28;",
            "nested": {"mnemonic": "alpha beta", "ok": "lead"},
            "key_hex": "ff" * 32,
        }
    )
    assert "private_key" not in payload
    assert "source_text" not in payload
    assert "mnemonic" not in payload["nested"]
    assert payload["nested"]["ok"] == "lead"
    assert "ff" * 32 not in str(payload)


def test_capture_outcome_excludes_secrets_and_stores_hash(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        outcome = capture_outcome(
            RUN_ID,
            "accepted",
            "hyp_01J00000000000000000000001",
            [{"gate": "B", "decision": "defect_pinned", "private_key": "0x" + "cd" * 32}],
            [{"tool_name": "foundry", "stdout_hash": "sha256:" + "a" * 64, "source": "secret"}],
            [{"content_hash": "sha256:" + "b" * 64, "exploit": "payload"}],
            store=store,
            hypothesis={
                "claim": "reentrancy after external call",
                "origin": "model_novel",
                "private_key": "0x" + "ab" * 32,
                "source_text": "contract Evil {}",
            },
            created_at=PINNED_TIME,
        )
        dumped = outcome.model_dump(mode="json")
        assert "private_key" not in str(dumped)
        assert "contract Evil" not in str(dumped)
        assert "0x" + "ab" * 32 not in str(dumped)
        assert outcome.content_hash.startswith("sha256:")
        assert outcome.promotion_stage == "quarantined"
        loaded = load_outcomes(store)
        assert loaded[0].outcome_id == outcome.outcome_id
    finally:
        store.close()


def test_capture_run_outcomes_reads_terminal_m6_state(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        hypo = seed_hypothesis(store, claim="duplicate known issue on withdraw")
        from ayran.evidence.service import transition

        transition(
            store,
            hypo["hypothesis_id"],
            "duplicate_known_issue",
            evidence={"duplicate_of": "hyp_01J00000000000000000000099", "comparison": "same root cause"},
        )
        result = capture_run_outcomes(store, run_id=RUN_ID, created_at=PINNED_TIME)
        assert result["count"] >= 1
        assert result["captured"]
    finally:
        store.close()
