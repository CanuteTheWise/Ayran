"""Shared M6 identities, sources, and graph helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ayran.evidence.actors import ACTOR_EVIDENCE
from ayran.evidence.service import transition
from ayran.hypotheses.builders import build_hypothesis
from ayran.router.persist import persist_hypotheses
from m5_fixtures import CLUSTER, CREATED, RUN_ID, TARGET_IDENTITY
from m5_fixtures import open_store as open_store

ROOT = Path(__file__).resolve().parents[2]
REENTRANT_SOURCE = (
    ROOT / "fixtures" / "evidence" / "reentrant-vault" / "src" / "ReentrantVault.sol"
).read_text(encoding="utf-8")
REENTRANT_PROJECT = ROOT / "fixtures" / "evidence" / "reentrant-vault"

SUPPORTED_EVIDENCE = {
    "path": "VulnerableVault.withdraw",
    "invariant": "withdraw pays only the caller's credited balance",
    "source_span": "VulnerableVault.sol:17",
    "preconditions_reachable": True,
    "reachable_preconditions": ["caller has a balance"],
    "evidence_ids": [],
}

TRUE_DEFECT_EVIDENCE = {
    "path": "ReentrantVault.withdraw",
    "invariant": "balances[msg.sender] is zeroed before any external call",
    "source_span": "ReentrantVault.sol:12",
    "preconditions_reachable": True,
    "reachable_preconditions": ["attacker contract with payable fallback"],
    "evidence_ids": [],
}

GATE_B_PASS: dict[str, Any] = {
    "clean_replay": {"passed": True, "detail": "fresh workspace matched stdout hash"},
    "numerical_assertions": {
        "passed": True,
        "detail": "before vault=2e18 after vault=0 attacker_net=+1e18",
    },
    "negative_controls": {"passed": True, "detail": "test_negative_control does not steal"},
    "defect_removal": {"passed": True, "detail": "CEI patch kills exploit", "exploit_persists": False},
    "fix_efficacy": {"passed": True, "detail": "deposit/withdraw still work", "feature_disabled": False},
    "alternate_paths": {"passed": True, "detail": "repeatable; unique trigger is fallback reenter"},
    "independent_skeptic": {"passed": True, "detail": "blind reviewer kept the finding"},
    "deployment_identity": {"passed": True, "detail": "repo-only; deployment not claimed", "claimed": False},
    "feasibility_scope_severity": {"passed": True, "detail": "unprivileged, in-scope, unique"},
    "negative_control_ids": ["evd_01J00000000000000000000002"],
    "fix_evidence_ids": ["evd_01J00000000000000000000003"],
    "evidence_ids": ["evd_01J00000000000000000000001"],
}

# R1: scripted challenger outputs (S9.2 transport seam). Gate A verdicts enter
# ONLY as these structurally complete submissions under a per-spawn credential.
CHALLENGER_SUBMISSION_FALSIFIED: dict[str, Any] = {
    "violated_invariant": "withdraw pays only the caller's own credited balance",
    "preconditions": [
        {
            "dimension": "access_boundaries",
            "present": True,
            "attacker_can_create": False,
            "detail": "withdraw settles against the caller's own credited balance only",
        },
        {
            "dimension": "require_guards",
            "present": True,
            "attacker_can_create": True,
            "detail": "require(balances[msg.sender] >= amount) holds for the caller",
        },
    ],
    "strongest_benign_explanation": (
        "withdraw credits then pays msg.sender with exactly that caller's balance "
        "(CEI held); this is a user withdrawal, not an arbitrary send"
    ),
    "cheapest_decisive_experiment": {
        "inputs": ["unprivileged caller holding one unit of credit"],
        "expected_positive": "attacker receives more than own credited balance",
        "expected_negative": "payout equals exactly the caller's credited balance",
        "capability": "foundry.test",
    },
    "verdict": "falsified",
}
CHALLENGER_SUBMISSION_POC_WORTHY: dict[str, Any] = {
    "violated_invariant": "balances[msg.sender] is zeroed before any external call",
    "preconditions": [
        {
            "dimension": "integration_behavior",
            "present": True,
            "attacker_can_create": True,
            "detail": "attacker contract with payable fallback re-enters withdraw",
        },
        {
            "dimension": "solvency",
            "present": True,
            "attacker_can_create": False,
            "detail": "vault must hold pooled deposits to drain",
        },
    ],
    "strongest_benign_explanation": (
        "no benign reading survives: the external call precedes the balance "
        "mutation on the quoted withdraw path"
    ),
    "cheapest_decisive_experiment": {
        "inputs": ["attacker contract deposit", "withdraw callback"],
        "expected_positive": "attacker net ETH increases; vault balance decreases twice",
        "expected_negative": "single withdraw without callback preserves conservation",
        "capability": "foundry.test",
    },
    "verdict": "poc_worthy",
}
CHALLENGER_SUBMISSION_MISSING_FACT: dict[str, Any] = {
    "violated_invariant": "deployed bytecode exposes only the audited withdraw path",
    "preconditions": [
        {
            "dimension": "deployment_identity",
            "present": False,
            "attacker_can_create": None,
            "detail": "pinned-block deployed bytecode identity is unknown",
        }
    ],
    "strongest_benign_explanation": (
        "the deployed proxy may route withdraw through a patched implementation"
    ),
    "cheapest_decisive_experiment": {
        "inputs": ["pinned-block bytecode diff versus repo source"],
        "expected_positive": "deployed selector set differs from repo source",
        "expected_negative": "bytecode matches repo source at the pinned block",
        "capability": "foundry.test",
    },
    "verdict": "needs_missing_fact",
}


def challenger_gate_a(
    store: Any,
    hypothesis_id: str,
    submission: dict[str, Any],
    *,
    child_id: str = "chd-01j",
    credentials: Any = None,
    reconcile: bool = False,
    transcript_hash: str | None = None,
) -> dict[str, Any]:
    """Scripted-challenger Gate A round trip: mint a per-spawn credential and submit."""

    from ayran.evidence.service import gate_a
    from ayran.gates.spawn_challenger import CredentialAuthority

    authority = credentials or CredentialAuthority(b"m6-test-authority")
    token = authority.mint_challenger(child_id=child_id)
    return gate_a(
        store,
        hypothesis_id,
        submission=submission,
        credential=token,
        credentials=authority,
        reconcile=reconcile,
        transcript_hash=transcript_hash,
    )


def seed_hypothesis(store: Any, *, claim: str, origin: str = "tool", **kwargs: Any) -> dict[str, Any]:
    item = build_hypothesis(
        origin=origin,
        claim=claim,
        cluster_id=CLUSTER,
        run_id=RUN_ID,
        created_at=CREATED,
        attack_path=list(kwargs.get("attack_path") or ["withdraw"]),
        target_entities=list(kwargs.get("target_entities") or []),
        preconditions=list(kwargs.get("preconditions") or ["unprivileged caller"]),
        impact_kind=str(kwargs.get("impact_kind") or "asset_theft"),
        impact_description=str(kwargs.get("impact_description") or "attacker can extract value"),
        novelty="unknown",
        trust_class=str(kwargs.get("trust_class") or "deterministic_tool"),
        root_cause=str(kwargs.get("root_cause") or claim),
        state=CLUSTER,
        attacker="unprivileged",
        target_identity=TARGET_IDENTITY,
    )
    persist_hypotheses(store, [item])
    loaded = json.loads(
        store.projection.connection.execute(
            "SELECT object_json FROM hypotheses WHERE hypothesis_id=? ORDER BY revision DESC LIMIT 1",
            (item["hypothesis_id"],),
        ).fetchone()[0]
    )
    return loaded if isinstance(loaded, dict) else item


def promote_supported(store: Any, hypothesis_id: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return transition(
        store,
        hypothesis_id,
        "supported",
        evidence=evidence or SUPPORTED_EVIDENCE,
        actor=ACTOR_EVIDENCE,
        cause="target-specific path and invariant",
    )
