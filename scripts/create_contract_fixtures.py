"""Create the deterministic M0 valid/invalid cross-language fixture corpus."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "fixtures" / "contracts"
TS = "2026-08-12T12:00:00Z"
RUN = "run_01J00000000000000000000001"
OTHER_RUN = "run_01J00000000000000000000002"
TARGET = "tgt_01J00000000000000000000001"
OTHER_TARGET = "tgt_01J00000000000000000000002"


def ident(prefix: str, number: int) -> str:
    return f"{prefix}_01J{number:023d}"


def digest(char: str = "a") -> str:
    return "sha256:" + char * 64


def actor(kind: str = "service", name: str = "ayran.fixture", full: bool = False) -> dict[str, Any]:
    value: dict[str, Any] = {"kind": kind, "id": name, "version": "1.0.0"}
    if full:
        value["independence_group"] = "fixture-independent"
    return value


def provenance(full: bool = False) -> dict[str, Any]:
    value: dict[str, Any] = {
        "provenance_id": ident("prv", 1),
        "source_uri": "https://fixtures.ayran.dev/m0",
        "source_version": "fixture-v1",
        "raw_hash": digest("b"),
        "retrieved_at": TS,
        "license_or_terms": "private-test-fixture",
        "transformation_lineage": [],
    }
    if full:
        value.update(
            {
                "extraction_locator": "fixture:1",
                "parser_version": "1.0.0",
                "transformation_lineage": [digest("c")],
            }
        )
    return value


def integrity(event: bool = False) -> dict[str, Any]:
    excluded = ["integrity.content_hash", "event_hash"] if event else ["integrity.content_hash"]
    return {
        "algorithm": "sha256",
        "canonicalization": "rfc8785",
        "content_hash": digest("0"),
        "excluded_fields": excluded,
    }


def target(target_id: str = TARGET) -> dict[str, Any]:
    return {
        "target_id": target_id,
        "source_tree_hash": digest("d"),
        "scope_id": ident("scp", 1),
        "commit": "1" * 40,
    }


def canonical_hash(value: dict[str, Any]) -> str:
    clone = copy.deepcopy(value)
    if isinstance(clone.get("integrity"), dict):
        clone["integrity"].pop("content_hash", None)
    clone.pop("event_hash", None)
    return "sha256:" + hashlib.sha256(rfc8785.dumps(clone)).hexdigest()


def seal(value: dict[str, Any]) -> dict[str, Any]:
    if isinstance(value.get("integrity"), dict):
        value["integrity"]["content_hash"] = canonical_hash(value)
    if "event_hash" in value:
        value["event_hash"] = canonical_hash(value)
    return value


def durable(
    id_field: str,
    value_id: str,
    full: bool = False,
    run: bool = True,
    target_bound: bool = True,
    event: bool = False,
) -> dict[str, Any]:
    value: dict[str, Any] = {"schema_version": "1.0.0", id_field: value_id, "created_at": TS}
    if run:
        value["run_id"] = RUN
    if target_bound:
        value["target_identity"] = target()
    value["provenance"] = [provenance(full)]
    value["integrity"] = integrity(event)
    return value


def objects() -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    common = {
        "schema_version": "1.0.0",
        "identifier": ident("obj", 1),
        "hash": digest(),
        "created_at": TS,
    }
    actor_min, actor_full = actor(), actor(full=True)
    prov_min, prov_full = provenance(), provenance(True)
    integ = integrity()

    event_min = durable("event_id", ident("evt", 1), event=True)
    event_min.update(
        {
            "seq": 1,
            "graph": "target",
            "aggregate_id": ident("hyp", 1),
            "aggregate_version": 1,
            "event_type": "hypothesis.created",
            "actor": actor(),
            "operation_id": ident("op", 1),
            "config_hash": digest("e"),
            "source_version": "target@fixture-v1",
            "idempotency_key": "fixture:event:1",
            "payload": {
                "contract_id": "hypothesis@1.0.0",
                "object_id": ident("hyp", 1),
                "content_hash": digest("f"),
            },
            "previous_event_hash": None,
            "event_hash": digest("0"),
        }
    )
    event_full = copy.deepcopy(event_min)
    event_full.update(
        {
            "seq": 2,
            "aggregate_version": 2,
            "event_type": "hypothesis.status_changed",
            "idempotency_key": "fixture:event:2",
            "previous_event_hash": digest("1"),
        }
    )

    node_min = durable("node_id", ident("nod", 1), target_bound=False)
    node_min.update(
        {
            "namespace": "target",
            "node_type": "Contract",
            "revision": 1,
            "status": "active",
            "properties": [],
            "trust_class": "deterministic_tool",
            "confidence": 1.0,
            "evidence_grade": "lead",
            "evidence_refs": [],
            "source_locator": "target/src/Vault.sol:1",
            "valid_from_event": ident("evt", 1),
        }
    )
    node_full = copy.deepcopy(node_min)
    node_full.update(
        {
            "properties": [{"name": "language", "value_type": "string", "value": "solidity"}],
            "evidence_refs": [ident("evd", 1)],
            "valid_to_event": None,
        }
    )

    edge_min = durable("edge_id", ident("edg", 1), target_bound=False)
    edge_min.update(
        {
            "namespace": "target",
            "edge_type": "CALLS",
            "source_id": ident("nod", 1),
            "target_id": ident("nod", 2),
            "revision": 1,
            "status": "active",
            "properties": [],
            "trust_class": "deterministic_tool",
            "confidence": 1.0,
            "evidence_grade": "lead",
            "evidence_refs": [],
            "source_locator": "target/src/Vault.sol:10",
            "valid_from_event": ident("evt", 1),
        }
    )
    edge_full = copy.deepcopy(edge_min)
    edge_full.update(
        {
            "properties": [{"name": "dispatch", "value_type": "string", "value": "external"}],
            "evidence_refs": [ident("evd", 1)],
            "valid_to_event": None,
        }
    )

    assertion_min = durable("assertion_id", ident("ast", 1), target_bound=False)
    assertion_min.update(
        {
            "namespace": "target",
            "subject_id": ident("nod", 1),
            "predicate": "has.asset.flow",
            "object_kind": "identifier",
            "object_value": ident("nod", 2),
            "writer": actor(),
            "written_at": TS,
            "source_version": "fixture-v1",
            "identity": {"kind": "target", "id": TARGET, "version_hash": digest("d")},
            "trust_class": "deterministic_tool",
            "confidence": 1.0,
            "artifact_refs": [],
            "valid_from_event": ident("evt", 1),
            "supersedes": [],
            "contradiction_group": None,
        }
    )
    assertion_full = copy.deepcopy(assertion_min)
    assertion_full.update(
        {
            "artifact_refs": [digest("e")],
            "supersedes": [ident("ast", 2)],
            "contradiction_group": ident("con", 1),
            "valid_to_event": None,
        }
    )

    capability_min = durable("capability_id", ident("cap", 1), run=False, target_bound=False)
    capability_min.update(
        {
            "version": "1.0.0",
            "kind": "executable_adapter",
            "ownership": "external_detect_only",
            "supports": {
                "languages": ["solidity"],
                "chains": ["evm"],
                "frameworks": ["foundry"],
                "phases": ["mapping", "validation"],
            },
            "triggers": ["build.foundry"],
            "questions_answered": ["Does behavior reproduce?"],
            "prerequisites": ["forge"],
            "detect": {"argv": ["forge", "--version"], "parser": "foundry-version-v1"},
            "health_check": {"method": "foundry.health"},
            "install_policy": {
                "allowed": False,
                "approval": "never",
                "checksum_required": True,
                "global_mutation_allowed": False,
            },
            "input_schema": "FoundryRequest@1.0.0",
            "output_schema": "FoundryResult@1.0.0",
            "invocation": {"argv_template": ["forge", "test", "--json"], "shell": False},
            "evidence_ceiling": "observed",
            "resources": {"cpu": 4, "memory_mib": 3072, "disk_mib": 4096, "network": "none"},
            "sandbox_profile": "evm-validator",
            "secret_aliases": [],
            "timeout_seconds": 900,
            "retry": {"transient": 1, "deterministic": 0},
            "cooldown": {"consecutive_failures": 2, "scope": "run"},
            "failure_taxonomy": ["prerequisite", "compile", "test", "timeout", "parser_drift"],
            "fallbacks": [],
            "cleanup": {
                "receipt_owned_only": True,
                "preserve_artifacts": True,
                "remove_external_dependencies": False,
            },
            "owner": "tools-evm",
            "last_verified": "2026-08-12",
        }
    )
    capability_full = copy.deepcopy(capability_min)
    capability_full.update(
        {"fallbacks": ["foundry.local-minimal"], "secret_aliases": ["AYRAN_RPC_SECRET_REF"]}
    )

    approval_classes = [
        "install_tool",
        "add_endpoint",
        "expand_scope",
        "external_upload",
        "submission",
        "signing",
        "spending",
        "transaction_broadcast",
    ]
    scope_min = durable("scope_id", ident("scp", 1), target_bound=False)
    scope_min.update(
        {
            "revision": 1,
            "target_identity": target(),
            "included_roots": ["target/src"],
            "excluded_roots": ["target/vendor"],
            "deployments": [],
            "chains": [1],
            "fork_blocks": [20000000],
            "rules": [
                {
                    "rule_id": ident("rul", 1),
                    "effect": "allow",
                    "action": "read_source",
                    "resource": "target/src",
                }
            ],
            "deny_overrides": True,
            "allowed_hosts": [],
            "allowed_endpoints": [],
            "allowed_tools": [],
            "write_roots": ["run/work"],
            "secret_aliases": [],
            "budgets": {
                "wall_minutes": 240,
                "token_units": 100000,
                "tool_seconds": 7200,
                "disk_mib": 8192,
            },
            "approval_rules": [
                {"action_class": value, "approval": "explicit-human"} for value in approval_classes
            ],
            "authorization": {
                "approved_by": actor("human", "operator"),
                "approved_scope_hash": digest("a"),
                "approved_at": TS,
            },
            "valid_from": TS,
            "valid_until": "2026-08-13T12:00:00Z",
        }
    )
    scope_full = copy.deepcopy(scope_min)
    scope_full.update(
        {
            "deployments": ["0x" + "1" * 40],
            "allowed_hosts": ["rpc.example.com"],
            "allowed_endpoints": ["https://rpc.example.com"],
            "allowed_tools": [ident("cap", 1)],
            "secret_aliases": ["AYRAN_RPC_SECRET_REF"],
        }
    )

    hypothesis_min = durable("hypothesis_id", ident("hyp", 1))
    hypothesis_min.update(
        {
            "origin": "model_novel",
            "claim": "Direct donation may desynchronize cached assets.",
            "invariant_ids": [ident("inv", 1)],
            "attack_path": ["donate assets", "mint mispriced shares"],
            "target_entities": [ident("nod", 1)],
            "preconditions": [
                {
                    "description": "Attacker can transfer assets directly",
                    "status": "observed",
                    "attacker_can_create": True,
                }
            ],
            "impact_premise": {
                "kind": "asset_theft",
                "description": "Share dilution may transfer value",
                "upper_bound": None,
            },
            "priors": [{"source": "model", "confidence": 0.4}],
            "novelty": "unknown",
            "required_falsifiers": ["Direct transfer does not change pricing"],
            "budget": {"token_units": 5000, "tool_seconds": 600, "wall_minutes": 30},
            "parent_ids": [],
            "duplicate_candidate_ids": [],
            "status": "lead",
            "evidence_grade": "lead",
            "trust_class": "model_observation",
            "confidence": 0.4,
            "transition_history": [
                {
                    "from": None,
                    "to": "lead",
                    "event_id": ident("evt", 1),
                    "actor": actor("model", "reasoner"),
                    "at": TS,
                    "evidence_ids": [],
                }
            ],
        }
    )
    hypothesis_full = copy.deepcopy(hypothesis_min)
    hypothesis_full.update(
        {
            "origin": "contradiction",
            "novelty": "variant",
            "status": "supported",
            "evidence_grade": "supported",
            "trust_class": "runtime_observation",
            "confidence": 0.8,
            "parent_ids": [ident("hyp", 2)],
            "duplicate_candidate_ids": [ident("hyp", 3)],
        }
    )

    evidence_min = durable("evidence_id", ident("evd", 1))
    evidence_min.update(
        {
            "artifact_hash": digest("1"),
            "size_bytes": 100,
            "mime_type": "application/json",
            "producer": actor("tool", "foundry"),
            "producer_version": "1.0.0",
            "input_hashes": [digest("2")],
            "config_hash": digest("3"),
            "fork_identity_hash": None,
            "raw_locator": "run/artifacts/raw.json",
            "normalized_locator": None,
            "evidence_grade": "observed",
            "trust_class": "runtime_observation",
            "confidence": 1.0,
            "supports": [ident("hyp", 1)],
            "refutes": [],
            "redaction": {"profile": "default", "secret_scan_passed": True, "redacted": False},
            "reproduction": {
                "argv": ["forge", "test", "--match-test", "testDonation"],
                "working_root": "run/work",
                "environment_hash": digest("4"),
                "expected_result_hash": digest("5"),
            },
        }
    )
    evidence_full = copy.deepcopy(evidence_min)
    evidence_full.update(
        {
            "normalized_locator": "run/artifacts/normalized.json",
            "fork_identity_hash": digest("6"),
            "refutes": [ident("hyp", 2)],
        }
    )

    tool_min = durable("tool_run_id", ident("trn", 1))
    tool_min.update(
        {
            "capability_id": ident("cap", 1),
            "capability_version": "1.0.0",
            "adapter_version": "1.0.0",
            "tool_name": "forge",
            "tool_version": "1.7.1",
            "argv": ["forge", "test"],
            "environment": [],
            "working_root": "run/work",
            "input_hashes": [digest("1")],
            "seed": None,
            "fork_identity_hash": None,
            "limits": {
                "cpu": 4,
                "memory_mib": 3072,
                "disk_mib": 4096,
                "wall_seconds": 900,
                "network": "none",
            },
            "started_at": TS,
            "ended_at": "2026-08-12T12:01:00Z",
            "exit_code": 0,
            "signal": None,
            "stdout_hash": digest("2"),
            "stderr_hash": digest("3"),
            "artifact_refs": [digest("4")],
            "parse_status": "parsed",
            "parser_version": "1.0.0",
            "normalized_evidence_ids": [ident("evd", 1)],
            "evidence_ceiling": "observed",
        }
    )
    tool_full = copy.deepcopy(tool_min)
    tool_full.update(
        {
            "seed": 7,
            "fork_identity_hash": digest("5"),
            "environment": [{"name": "FOUNDRY_PROFILE", "value": "ayran"}],
        }
    )

    coverage_min = durable("coverage_cell_id", ident("cov", 1))
    coverage_min.update(
        {
            "dimension": "share accounting direct donation",
            "target_refs": [ident("nod", 1)],
            "invariant_ids": [ident("inv", 1)],
            "entry_point_ids": [ident("nod", 2)],
            "attempted_origins": ["model_novel"],
            "attempted_tools": [],
            "depth": "reviewed",
            "achieved_evidence_grade": "lead",
            "status": "open",
            "examined_result": "Direct donation path identified; exploitability not yet tested",
            "gaps": ["negative control"],
            "blockers": [],
            "untried_dimensions": ["rounding boundaries"],
            "updated_at": TS,
        }
    )
    coverage_full = copy.deepcopy(coverage_min)
    coverage_full.update(
        {
            "attempted_origins": ["model_novel", "tool"],
            "attempted_tools": [ident("cap", 1)],
            "depth": "tested",
            "achieved_evidence_grade": "observed",
            "status": "examined",
            "gaps": [],
            "blockers": [],
        }
    )

    verdict_min = durable("verdict_id", ident("dav", 1))
    verdict_min.update(
        {
            "gate": "A",
            "decision": "advance",
            "resulting_hypothesis_status": "poc_worthy",
            "hypothesis_id": ident("hyp", 1),
            "evidence_ids": [ident("evd", 1)],
            "falsification_attempts": [
                {
                    "question": "Can the guard prevent the path?",
                    "result": "No guard blocks direct transfer",
                    "evidence_ids": [ident("evd", 1)],
                    "untried_dimensions": ["alternate token behavior"],
                }
            ],
            "causal_chain": ["donation changes assets", "cached value remains stale"],
            "dissent": [],
            "confidence": 0.8,
            "deterministic_rule_version": "1.0.0",
            "reviewer": actor("gate", "devils-advocate-a", True),
            "independent_from": [ident("hyp", 1)],
        }
    )
    verdict_full = copy.deepcopy(verdict_min)
    verdict_full.update(
        {
            "gate": "B",
            "decision": "advance",
            "resulting_hypothesis_status": "defect_pinned",
            "dissent": ["Deployment configuration still requires confirmation"],
        }
    )

    finding_min = durable("finding_id", ident("fnd", 1))
    finding_min.update(
        {
            "status": "candidate",
            "title": "Donation may dilute vault shares",
            "root_cause": "Cached assets omit direct transfers",
            "violated_invariant": "Shares preserve proportional ownership",
            "affected_code": ["target/src/Vault.sol:10"],
            "attacker_model": "Unprivileged user with underlying assets",
            "preconditions": ["Direct transfer is possible"],
            "impact": {
                "kind": "theft",
                "equation": "attacker_gain = victim_loss",
                "lower_bound": "0",
                "upper_bound": None,
                "assumptions": ["market exists"],
            },
            "evidence_ids": [ident("evd", 1)],
            "trust_class": "runtime_observation",
            "confidence": 0.8,
        }
    )
    finding_full = copy.deepcopy(finding_min)
    finding_full.update(
        {
            "status": "validated",
            "gate_a_verdict_id": ident("dav", 1),
            "gate_b_verdict_id": ident("dav", 2),
            "reproduction_artifact_id": ident("evd", 1),
            "negative_control_ids": [ident("evd", 2)],
            "defect_fix_evidence_ids": [ident("evd", 3)],
            "scope_manifest_id": ident("scp", 1),
            "duplicate_disposition": {
                "status": "unique",
                "comparison": "No matching known issue",
                "source_refs": [],
            },
            "severity": {
                "label": "high",
                "policy_id": ident("pol", 1),
                "rule_citation": "Loss of user assets",
            },
            "uncertainty": ["Exact deployed balance unknown"],
            "mitigations": ["Include live balance in accounting"],
        }
    )

    learning_min = durable("learning_outcome_id", ident("lrn", 1))
    learning_min.update(
        {
            "promotion_stage": "quarantined",
            "result": "accepted",
            "adjudication": "Fixture outcome accepted",
            "generalized_candidate": None,
            "source_lineage": [digest("1")],
            "rights": {
                "license_or_terms": "private",
                "redistribution_allowed": False,
                "reviewed": False,
            },
            "contamination_class": "development",
        }
    )
    learning_full = copy.deepcopy(learning_min)
    learning_full.update(
        {
            "promotion_stage": "released",
            "generalized_candidate": "Direct-transfer accounting lens",
            "rights": {
                "license_or_terms": "private",
                "redistribution_allowed": False,
                "reviewed": True,
            },
            "reviewers": [
                actor("human", "operator"),
                actor("service", "independent-reviewer", True),
            ],
            "positive_test_ids": [ident("tst", 1)],
            "hard_negative_test_ids": [ident("tst", 2)],
            "held_out_evaluation": {
                "evaluation_id": ident("evl", 1),
                "passed": True,
                "result_hash": digest("2"),
                "project_families": 2,
            },
            "release_pointer": ident("rel", 1),
            "rollback_pointer": ident("rel", 2),
            "promotion_approved_by": actor("human", "operator"),
        }
    )

    context_min = durable("context_pack_id", ident("ctx", 1))
    context_min.update(
        {
            "purpose": "Gate A review",
            "role": "knowledge-blind-challenger",
            "graph_cursor": 10,
            "query_ids": [ident("qry", 1)],
            "included_object_ids": [ident("hyp", 1)],
            "included_evidence_ids": [ident("evd", 1)],
            "excluded_object_ids": [],
            "omitted_counts": {"target": 0, "global": 10, "learning": 0},
            "token_estimate": 500,
            "policy_checksum": digest("1"),
            "config_checksum": digest("2"),
            "based_on_event_hash": digest("3"),
            "fresh_until_event": None,
            "knowledge_policy": "knowledge_blind",
            "sections": [
                {
                    "classification": "POLICY",
                    "title": "Scope",
                    "content": "Operate only within approved scope.",
                    "source_ids": [ident("scp", 1)],
                }
            ],
        }
    )
    context_full = copy.deepcopy(context_min)
    context_full.update(
        {
            "knowledge_policy": "graph_aware",
            "sections": context_min["sections"]
            + [
                {
                    "classification": "HISTORICAL_REFERENCE",
                    "title": "Donation lens",
                    "content": "Historical reference; not target evidence.",
                    "source_ids": [ident("src", 1)],
                }
            ],
        }
    )

    router_min = durable("router_action_id", ident("rta", 1))
    router_min.update(
        {
            "triggering_event_ids": [ident("evt", 1)],
            "policy_version": "1.0.0",
            "deduplication_key": "gate-a:hyp-1",
            "handler": {"kind": "service", "id": "gate-a", "version": "1.0.0"},
            "priority": 100,
            "budget_effect": {"token_units": 1000, "tool_seconds": 0, "wall_minutes": 10},
            "dependencies": [],
            "authorization": {
                "decision": "allow",
                "scope_manifest_id": ident("scp", 1),
                "rule_ids": [ident("rul", 1)],
                "decided_by": actor("router", "policy-router"),
                "decided_at": TS,
                "reason": "In scope and budget",
            },
            "status": "eligible",
            "context_pack_id": ident("ctx", 1),
            "owner": actor("router", "policy-router"),
            "deadline": "2026-08-12T13:00:00Z",
            "stop_condition": "One decisive verdict",
            "emitted_operation_ids": [],
            "result_ids": [],
        }
    )
    router_full = copy.deepcopy(router_min)
    router_full.update(
        {
            "status": "succeeded",
            "emitted_operation_ids": [ident("op", 1)],
            "result_ids": [ident("dav", 1)],
        }
    )

    stream = {
        "namespace": "target",
        "stream_id": ident("str", 1),
        "run_id": RUN,
        "target_identity": target(),
        "target_key": digest("d"),
    }
    embedded_node = copy.deepcopy(node_min)
    embedded_node["valid_from_event"] = ident("evt", 20)
    seal(embedded_node)
    journal_event_min = {
        "schema_version": "1.0.0",
        "journal_format_version": 1,
        "event_id": ident("evt", 20),
        "seq": 1,
        "stream": stream,
        "batch_id": ident("bat", 1),
        "ordinal": 1,
        "aggregate_id": embedded_node["node_id"],
        "aggregate_version": 1,
        "event_type": "node.created",
        "actor": actor(),
        "operation_id": ident("op", 20),
        "causation_id": None,
        "created_at": TS,
        "provenance": [provenance()],
        "integrity": integrity(event=True),
        "config_hash": digest("e"),
        "source_version": "target@fixture-v1",
        "idempotency_key": "fixture:journal:1",
        "body": {
            "contract_id": "graph-node@1.0.0",
            "object_id": embedded_node["node_id"],
            "content_hash": embedded_node["integrity"]["content_hash"],
            "value": embedded_node,
            "transition": {"kind": "snapshot", "reason": None, "supersedes": []},
        },
        "previous_event_hash": None,
        "event_hash": digest("0"),
    }
    seal(journal_event_min)
    journal_event_full = copy.deepcopy(journal_event_min)
    revised_node = copy.deepcopy(embedded_node)
    revised_node["revision"] = 2
    revised_node["valid_from_event"] = ident("evt", 21)
    seal(revised_node)
    journal_event_full.update(
        {
            "event_id": ident("evt", 21),
            "seq": 2,
            "ordinal": 2,
            "aggregate_version": 2,
            "event_type": "node.revised",
            "causation_id": ident("op", 19),
            "previous_event_hash": journal_event_min["event_hash"],
            "body": {
                "contract_id": "graph-node@1.0.0",
                "object_id": revised_node["node_id"],
                "content_hash": revised_node["integrity"]["content_hash"],
                "value": revised_node,
                "transition": {
                    "kind": "snapshot",
                    "reason": "Fixture revision",
                    "supersedes": [journal_event_min["event_id"]],
                },
            },
        }
    )
    seal(journal_event_full)

    journal_begin = {
        "schema_version": "1.0.0",
        "journal_format_version": 1,
        "hash_domain": "ayran.journal.begin.v1",
        "record_type": "batch.begin",
        "stream": stream,
        "batch_id": ident("bat", 1),
        "operation_id": ident("op", 20),
        "causation_id": None,
        "idempotency_key": "fixture:journal:1",
        "request_hash": digest("1"),
        "expected_revisions": [{"aggregate_id": embedded_node["node_id"], "revision": 0}],
        "first_seq": 1,
        "event_count": 1,
        "previous_event_hash": None,
        "previous_commit_hash": None,
        "created_at": TS,
    }
    journal_member = {
        "schema_version": "1.0.0",
        "journal_format_version": 1,
        "record_type": "batch.event",
        "event": journal_event_min,
    }

    ack_min = {
        "schema_version": "1.0.0",
        "journal_format_version": 1,
        "stream": stream,
        "batch_id": ident("bat", 1),
        "operation_id": ident("op", 20),
        "idempotency_key": "fixture:journal:1",
        "request_hash": digest("1"),
        "first_seq": 1,
        "last_seq": 1,
        "event_ids": [journal_event_min["event_id"]],
        "event_hashes": [journal_event_min["event_hash"]],
        "commit_hash": digest("2"),
        "projection_cursor": 1,
        "projection_event_hash": journal_event_min["event_hash"],
        "idempotent_replay": False,
    }
    ack_full = copy.deepcopy(ack_min)
    ack_full["idempotent_replay"] = True

    checkpoint_min = {
        "schema_version": "1.0.0",
        "checkpoint_id": ident("chk", 1),
        "created_at": TS,
        "stream": stream,
        "journal_cursor": 1,
        "journal_event_hash": journal_event_min["event_hash"],
        "journal_commit_hash": digest("2"),
        "projection_schema_version": "1.0.0",
        "migration_version": 1,
        "target_hash": digest("d"),
        "config_hash": digest("e"),
        "source_hash": None,
        "tool_hash": None,
        "artifact_manifest_hash": None,
        "outbox_digest": digest("3"),
        "projection_digest": digest("4"),
        "integrity": integrity(),
    }
    checkpoint_full = copy.deepcopy(checkpoint_min)
    checkpoint_full.update(
        {"source_hash": digest("5"), "tool_hash": digest("6"), "artifact_manifest_hash": digest("7")}
    )

    manifest_min = {
        "schema_version": "1.0.0",
        "journal_format_version": 1,
        "segment_id": ident("seg", 1),
        "segment_name": "000001.jsonl",
        "stream": stream,
        "first_seq": 1,
        "last_seq": 1,
        "first_event_hash": journal_event_min["event_hash"],
        "last_event_hash": journal_event_min["event_hash"],
        "first_commit_hash": digest("2"),
        "last_commit_hash": digest("2"),
        "previous_manifest_hash": None,
        "event_count": 1,
        "batch_count": 1,
        "byte_size": 1024,
        "file_hash": digest("8"),
        "merkle_root": digest("9"),
        "backup_state": "pending",
        "created_at": TS,
        "closed_at": TS,
        "integrity": integrity(),
    }
    manifest_full = copy.deepcopy(manifest_min)
    manifest_full.update({"backup_state": "verified", "previous_manifest_hash": digest("a")})

    report_min = {
        "schema_version": "1.0.0",
        "report_id": ident("rpt", 1),
        "created_at": TS,
        "operation": "verify",
        "stream": stream,
        "status": "ok",
        "journal_cursor": 1,
        "projection_cursor": 1,
        "last_event_hash": journal_event_min["event_hash"],
        "last_commit_hash": digest("2"),
        "verified_segments": 1,
        "verified_batches": 1,
        "verified_events": 1,
        "issues": [],
        "recovered_suffix_hash": None,
        "query_digest": digest("4"),
        "integrity": integrity(),
    }
    report_full = copy.deepcopy(report_min)
    report_full.update(
        {
            "status": "recovered",
            "recovered_suffix_hash": digest("b"),
            "issues": [
                {
                    "code": "TRAILING_PARTIAL_RECORD",
                    "message": "Recovered an uncommitted trailing suffix.",
                    "segment": "000001.jsonl",
                    "line": 4,
                    "retryable": False,
                }
            ],
        }
    )

    query_min = {
        "schema_version": "1.0.0",
        "query_api_version": "1.0.0",
        "query_id": ident("qry", 20),
        "created_at": TS,
        "stream": stream,
        "query_name": "entity.get",
        "canonical_params": {"entity_id": embedded_node["node_id"]},
        "snapshot": {
            "as_of_seq": 1,
            "event_hash": journal_event_min["event_hash"],
            "projection_schema_version": "1.0.0",
            "migration_version": 1,
        },
        "records": [{"kind": "node", "value": embedded_node}],
        "truncated": False,
        "index_degraded": False,
        "query_digest": digest("4"),
    }
    query_full = copy.deepcopy(query_min)
    query_full.update({"truncated": True, "index_degraded": True})

    return {
        "common": (common, copy.deepcopy(common)),
        "actor": (actor_min, actor_full),
        "provenance": (prov_min, prov_full),
        "integrity": (integ, copy.deepcopy(integ)),
        "graph-event": (event_min, event_full),
        "graph-node": (node_min, node_full),
        "graph-edge": (edge_min, edge_full),
        "graph-assertion": (assertion_min, assertion_full),
        "journal-event": (journal_event_min, journal_event_full),
        "journal-record": (journal_begin, journal_member),
        "graph-acknowledgement": (ack_min, ack_full),
        "graph-checkpoint": (checkpoint_min, checkpoint_full),
        "segment-manifest": (manifest_min, manifest_full),
        "graph-integrity-report": (report_min, report_full),
        "graph-query-result": (query_min, query_full),
        "capability-manifest": (capability_min, capability_full),
        "scope-manifest": (scope_min, scope_full),
        "hypothesis": (hypothesis_min, hypothesis_full),
        "evidence-artifact": (evidence_min, evidence_full),
        "tool-run": (tool_min, tool_full),
        "coverage-cell": (coverage_min, coverage_full),
        "da-verdict": (verdict_min, verdict_full),
        "finding": (finding_min, finding_full),
        "learning-outcome": (learning_min, learning_full),
        "context-pack": (context_min, context_full),
        "router-action": (router_min, router_full),
    }


def invalids(
    name: str, minimal: dict[str, Any], full: dict[str, Any]
) -> list[tuple[str, dict[str, Any], str, dict[str, str] | None]]:
    rows: list[tuple[str, dict[str, Any], str, dict[str, str] | None]] = []
    unknown = copy.deepcopy(minimal)
    unknown["unexpected_security_field"] = "reject"
    rows.append(("unknown-property", unknown, "additional property", None))
    if "provenance" in minimal:
        missing = copy.deepcopy(minimal)
        missing.pop("provenance")
        rows.append(("missing-provenance", missing, "provenance", None))
    else:
        bad = copy.deepcopy(minimal)
        key = "schema_version" if "schema_version" in bad else next(iter(bad))
        bad.pop(key)
        rows.append(("missing-required", bad, key, None))
    if name == "common":
        bad = copy.deepcopy(minimal)
        bad["hash"] = "sha256:xyz"
        rows.append(("invalid-hash", bad, "hash", None))
        bad = copy.deepcopy(minimal)
        bad["schema_version"] = "1.0"
        rows.append(("invalid-version", bad, "version", None))
    elif name == "actor":
        bad = copy.deepcopy(minimal)
        bad["kind"] = "anonymous"
        rows.append(("invalid-actor-kind", bad, "kind", None))
    elif name == "provenance":
        bad = copy.deepcopy(minimal)
        bad["raw_hash"] = "bad"
        rows.append(("invalid-raw-hash", bad, "hash", None))
    elif name == "integrity":
        bad = copy.deepcopy(minimal)
        bad["canonicalization"] = "custom"
        rows.append(("unsupported-canonicalization", bad, "canonicalization", None))
    elif name == "graph-event":
        bad = copy.deepcopy(minimal)
        bad["seq"] = 0
        rows.append(("invalid-sequence", bad, "seq", None))
        bad = copy.deepcopy(minimal)
        bad["previous_event_hash"] = digest("1")
        seal(bad)
        rows.append(("malformed-genesis-predecessor", bad, "genesis", None))
        bad = copy.deepcopy(minimal)
        bad["event_hash"] = digest("9")
        rows.append(("invalid-event-hash", bad, "event_hash", None))
    elif name in {"graph-node", "graph-edge", "graph-assertion"}:
        bad = copy.deepcopy(minimal)
        bad["trust_class"] = "model_certified"
        rows.append(("unsupported-trust", bad, "trust", None))
    elif name == "journal-event":
        bad = copy.deepcopy(minimal)
        bad["journal_format_version"] = 2
        rows.append(("unsupported-format", bad, "format", None))
    elif name == "journal-record":
        bad = copy.deepcopy(minimal)
        bad["record_type"] = "batch.unknown"
        rows.append(("unsupported-record", bad, "record", None))
    elif name == "graph-acknowledgement":
        bad = copy.deepcopy(minimal)
        bad["event_hashes"] = []
        rows.append(("missing-event-hashes", bad, "event", None))
    elif name == "graph-checkpoint":
        bad = copy.deepcopy(minimal)
        bad["migration_version"] = 0
        rows.append(("invalid-migration", bad, "migration", None))
    elif name == "segment-manifest":
        bad = copy.deepcopy(minimal)
        bad["segment_name"] = "active.jsonl"
        rows.append(("invalid-segment-name", bad, "segment", None))
    elif name == "graph-integrity-report":
        bad = copy.deepcopy(minimal)
        bad["status"] = "repaired"
        rows.append(("invalid-status", bad, "status", None))
    elif name == "graph-query-result":
        bad = copy.deepcopy(minimal)
        bad["query_name"] = "Entity Get"
        rows.append(("invalid-query-name", bad, "query", None))
    elif name == "capability-manifest":
        bad = copy.deepcopy(minimal)
        bad["invocation"]["shell"] = True
        rows.append(("shell-invocation", bad, "shell", None))
        bad = copy.deepcopy(minimal)
        bad["secret_aliases"] = ["RAW_PRIVATE_KEY"]
        rows.append(("raw-secret-name", bad, "secret", None))
    elif name == "scope-manifest":
        bad = copy.deepcopy(minimal)
        bad["deny_overrides"] = False
        rows.append(("deny-does-not-override", bad, "deny", None))
        bad = copy.deepcopy(minimal)
        bad["rules"].append(
            {
                "rule_id": ident("rul", 2),
                "effect": "deny",
                "action": "read_source",
                "resource": "target/src",
            }
        )
        seal(bad)
        rows.append(("ambiguous-allow-deny", bad, "ambiguous", None))
    elif name == "hypothesis":
        bad = copy.deepcopy(minimal)
        bad["origin"] = "historical"
        rows.append(("invalid-origin", bad, "origin", None))
        bad = copy.deepcopy(minimal)
        bad["schema_version"] = "1.0"
        rows.append(("invalid-version", bad, "version", None))
    elif name == "evidence-artifact":
        bad = copy.deepcopy(minimal)
        bad["target_identity"]["target_id"] = OTHER_TARGET
        seal(bad)
        rows.append(("wrong-target", bad, "target_id", {"run_id": RUN, "target_id": TARGET}))
        bad = copy.deepcopy(minimal)
        bad["run_id"] = OTHER_RUN
        seal(bad)
        rows.append(("wrong-run", bad, "run_id", {"run_id": RUN, "target_id": TARGET}))
        bad = copy.deepcopy(minimal)
        bad["evidence_grade"] = "validated"
        bad["trust_class"] = "model_observation"
        seal(bad)
        rows.append(("model-cannot-validate", bad, "model or historical", None))
    elif name == "tool-run":
        bad = copy.deepcopy(minimal)
        bad["evidence_ceiling"] = "validated"
        rows.append(("unsupported-evidence-ceiling", bad, "ceiling", None))
        bad = copy.deepcopy(minimal)
        bad["argv"] = "forge test"
        rows.append(("shell-string-instead-of-argv", bad, "argv", None))
    elif name == "coverage-cell":
        bad = copy.deepcopy(minimal)
        bad["examined_result"] = "safe"
        rows.append(("global-safe-claim", bad, "safe", None))
    elif name == "da-verdict":
        bad = copy.deepcopy(minimal)
        bad["resulting_hypothesis_status"] = "validated"
        rows.append(("invalid-decision-status-map", bad, "status", None))
    elif name == "finding":
        bad = copy.deepcopy(full)
        bad.pop("gate_b_verdict_id")
        rows.append(("validated-without-gate-b", bad, "gate_b", None))
        bad = copy.deepcopy(full)
        bad["negative_control_ids"] = []
        rows.append(("validated-without-negative-control", bad, "negative", None))
    elif name == "learning-outcome":
        bad = copy.deepcopy(full)
        bad.pop("reviewers")
        rows.append(("promotion-without-review", bad, "review", None))
        bad = copy.deepcopy(full)
        bad["held_out_evaluation"]["passed"] = False
        rows.append(("failed-held-out-promotion", bad, "passed", None))
    elif name == "context-pack":
        bad = copy.deepcopy(minimal)
        bad["policy_checksum"] = "bad"
        rows.append(("invalid-policy-hash", bad, "hash", None))
    elif name == "router-action":
        bad = copy.deepcopy(minimal)
        bad.pop("authorization")
        rows.append(("missing-authorization", bad, "authorization", None))
        bad = copy.deepcopy(full)
        bad["result_ids"] = []
        rows.append(("success-without-result", bad, "result", None))
    return rows


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    manifest: list[dict[str, Any]] = []
    for name, (minimum, full) in objects().items():
        seal(minimum)
        seal(full)
        for variant, value in (("minimal", minimum), ("full", full)):
            relative = Path(name) / "valid" / f"{variant}.json"
            write(OUT / relative, value)
            manifest.append(
                {
                    "contract": name,
                    "path": relative.as_posix(),
                    "expected": "valid",
                    "variant": variant,
                }
            )
        for invalid_name, value, reason, context in invalids(name, minimum, full):
            relative = Path(name) / "invalid" / f"{invalid_name}.json"
            write(OUT / relative, value)
            row: dict[str, Any] = {
                "contract": name,
                "path": relative.as_posix(),
                "expected": "invalid",
                "reason_contains": reason,
            }
            if context:
                row["context"] = context
            manifest.append(row)
    write(OUT / "manifest.json", {"schema_version": "1.0.0", "fixtures": manifest})
    print(f"Wrote {len(manifest)} fixtures for {len(objects())} contracts")


if __name__ == "__main__":
    main()
