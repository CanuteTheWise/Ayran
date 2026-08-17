"""Four sealed CapabilityManifest documents for M4 adapters."""

from __future__ import annotations

from typing import Any

from ayran.graph.canonical import object_hash
from ayran.tools.types import (
    CAP_FOUNDRY,
    CAP_SLITHER,
    CAP_SOLC,
    CAP_SOLODIT,
    PRV_FOUNDRY,
    PRV_SLITHER,
    PRV_SOLC,
    PRV_SOLODIT,
    ZERO_HASH,
)

CREATED = "2026-08-13T00:00:00Z"
VERIFIED = "2026-08-13"


def _integrity() -> dict[str, Any]:
    return {
        "algorithm": "sha256",
        "canonicalization": "rfc8785",
        "content_hash": ZERO_HASH,
        "excluded_fields": ["integrity.content_hash"],
    }


def _provenance(provenance_id: str, source: str, version: str) -> dict[str, Any]:
    return {
        "provenance_id": provenance_id,
        "source_uri": f"https://ayran.dev/capabilities/{source}",
        "source_version": version,
        "raw_hash": ZERO_HASH,
        "retrieved_at": CREATED,
        "license_or_terms": "external-detect-only",
        "transformation_lineage": [],
    }


def seal(manifest: dict[str, Any]) -> dict[str, Any]:
    provenance = manifest.get("provenance")
    if isinstance(provenance, list) and provenance and isinstance(provenance[0], dict):
        identity = {
            "capability_id": manifest.get("capability_id"),
            "alias": (manifest.get("triggers") or [""])[0],
            "version": manifest.get("version"),
        }
        provenance[0]["raw_hash"] = object_hash(identity)
    manifest["integrity"] = _integrity()
    manifest["integrity"]["content_hash"] = object_hash(manifest)
    return manifest


def solc_manifest() -> dict[str, Any]:
    return seal(
        {
            "schema_version": "1.0.0",
            "capability_id": CAP_SOLC,
            "created_at": CREATED,
            "version": "1.0.0",
            "kind": "executable_adapter",
            "ownership": "external_detect_only",
            "supports": {
                "languages": ["solidity"],
                "chains": ["evm"],
                "frameworks": ["solc"],
                "phases": ["mapping", "validation"],
            },
            "triggers": ["solc.compile", "build.solc"],
            "questions_answered": ["does_the_target_compile", "which_solc_version_was_resolved"],
            "prerequisites": ["solc"],
            "detect": {"argv": ["solc", "--version"], "parser": "solc_version_v1"},
            "health_check": {"method": "solc_health_v1"},
            "install_policy": {
                "allowed": False,
                "approval": "always",
                "checksum_required": True,
                "global_mutation_allowed": False,
            },
            "input_schema": "SolcCompileRequest@1.0.0",
            "output_schema": "SolcCompileResult@1.0.0",
            "invocation": {
                "argv_template": ["solc", "--optimize", "--output-dir", "{output_dir}", "{source_paths}"],
                "shell": False,
            },
            "evidence_ceiling": "observed",
            "resources": {"cpu": 2, "memory_mib": 1024, "disk_mib": 256, "network": "none"},
            "sandbox_profile": "evm-compiler",
            "secret_aliases": [],
            "timeout_seconds": 120,
            "retry": {"transient": 0, "deterministic": 0},
            "cooldown": {"consecutive_failures": 2, "scope": "run"},
            "failure_taxonomy": ["prerequisite", "compile", "parser_drift", "timeout"],
            "fallbacks": [],
            "cleanup": {
                "receipt_owned_only": True,
                "preserve_artifacts": True,
                "remove_external_dependencies": False,
            },
            "owner": "tools-evm",
            "last_verified": VERIFIED,
            "provenance": [_provenance(PRV_SOLC, "solc.compile", "0.8.28")],
        }
    )


def foundry_manifest() -> dict[str, Any]:
    return seal(
        {
            "schema_version": "1.0.0",
            "capability_id": CAP_FOUNDRY,
            "created_at": CREATED,
            "version": "1.0.0",
            "kind": "executable_adapter",
            "ownership": "external_detect_only",
            "supports": {
                "languages": ["solidity"],
                "chains": ["evm"],
                "frameworks": ["foundry"],
                "phases": ["mapping", "validation", "falsification"],
            },
            "triggers": ["foundry.test", "build.foundry"],
            "questions_answered": ["does_behavior_reproduce", "does_fix_kill_behavior"],
            "prerequisites": ["forge", "compatible_solc", "writable_run_copy"],
            "detect": {"argv": ["forge", "--version"], "parser": "foundry_version_v1"},
            "health_check": {"method": "foundry_health_v1"},
            "install_policy": {
                "allowed": False,
                "approval": "always",
                "checksum_required": True,
                "global_mutation_allowed": False,
            },
            "input_schema": "FoundryRunRequest@1.0.0",
            "output_schema": "FoundryRunResult@1.0.0",
            "invocation": {"argv_template": ["forge", "test", "--json"], "shell": False},
            "evidence_ceiling": "observed",
            "resources": {"cpu": 4, "memory_mib": 3072, "disk_mib": 4096, "network": "rpc-allowlist"},
            "sandbox_profile": "evm-validator",
            "secret_aliases": ["AYRAN_RPC_SECRET_REF"],
            "timeout_seconds": 900,
            "retry": {"transient": 1, "deterministic": 0},
            "cooldown": {"consecutive_failures": 2, "scope": "run"},
            "failure_taxonomy": [
                "prerequisite",
                "compile",
                "test",
                "timeout",
                "oom",
                "rpc",
                "parser_drift",
            ],
            "fallbacks": ["foundry.local_minimal"],
            "cleanup": {
                "receipt_owned_only": True,
                "preserve_artifacts": True,
                "remove_external_dependencies": False,
            },
            "owner": "tools-evm",
            "last_verified": VERIFIED,
            "provenance": [_provenance(PRV_FOUNDRY, "foundry.test", "1.7.1")],
        }
    )


def slither_manifest() -> dict[str, Any]:
    return seal(
        {
            "schema_version": "1.0.0",
            "capability_id": CAP_SLITHER,
            "created_at": CREATED,
            "version": "1.0.0",
            "kind": "executable_adapter",
            "ownership": "external_detect_only",
            "supports": {
                "languages": ["solidity"],
                "chains": ["evm"],
                "frameworks": ["slither"],
                "phases": ["mapping", "discovery"],
            },
            "triggers": ["slither.analyze"],
            "questions_answered": ["which_static_alerts_exist", "where_are_the_source_spans"],
            "prerequisites": ["slither"],
            "detect": {"argv": ["slither", "--version"], "parser": "slither_version_v1"},
            "health_check": {"method": "slither_health_v1"},
            "install_policy": {
                "allowed": False,
                "approval": "always",
                "checksum_required": True,
                "global_mutation_allowed": False,
            },
            "input_schema": "SlitherRunRequest@1.0.0",
            "output_schema": "SlitherRunResult@1.0.0",
            "invocation": {
                "argv_template": ["slither", "--json", "{output_file}", "{source_paths}"],
                "shell": False,
            },
            "evidence_ceiling": "lead",
            "resources": {"cpu": 2, "memory_mib": 2048, "disk_mib": 512, "network": "none"},
            "sandbox_profile": "evm-static",
            "secret_aliases": [],
            "timeout_seconds": 300,
            "retry": {"transient": 0, "deterministic": 0},
            "cooldown": {"consecutive_failures": 2, "scope": "run"},
            "failure_taxonomy": ["prerequisite", "compile", "parser_drift", "timeout", "oom"],
            "fallbacks": [],
            "cleanup": {
                "receipt_owned_only": True,
                "preserve_artifacts": True,
                "remove_external_dependencies": False,
            },
            "owner": "tools-evm",
            "last_verified": VERIFIED,
            "provenance": [_provenance(PRV_SLITHER, "slither.analyze", "0.11.5")],
        }
    )


def solodit_manifest() -> dict[str, Any]:
    return seal(
        {
            "schema_version": "1.0.0",
            "capability_id": CAP_SOLODIT,
            "created_at": CREATED,
            "version": "1.0.0",
            "kind": "http_adapter",
            "ownership": "external_detect_only",
            "supports": {
                "languages": ["solidity"],
                "chains": ["evm"],
                "frameworks": [],
                "phases": ["discovery", "dedup", "reporting"],
            },
            "triggers": ["solodit.search"],
            "questions_answered": [
                "are_there_historical_precedents",
                "what_is_the_citation_for_a_known_issue",
            ],
            "prerequisites": ["solodit_endpoint"],
            "detect": {"argv": ["solodit", "health"], "parser": "solodit_health_v1"},
            "health_check": {"method": "http_health_check"},
            "install_policy": {
                "allowed": False,
                "approval": "always",
                "checksum_required": True,
                "global_mutation_allowed": False,
            },
            "input_schema": "SoloditSearchRequest@1.0.0",
            "output_schema": "SoloditSearchResult@1.0.0",
            "invocation": {
                "argv_template": ["solodit", "search", "{query}"],
                "shell": False,
            },
            "evidence_ceiling": "lead",
            "resources": {"cpu": 1, "memory_mib": 256, "disk_mib": 64, "network": "approved-api"},
            "sandbox_profile": "evm-knowledge",
            "secret_aliases": ["AYRAN_SOLODIT_SECRET_REF"],
            "timeout_seconds": 30,
            "retry": {"transient": 1, "deterministic": 0},
            "cooldown": {"consecutive_failures": 3, "scope": "run"},
            "failure_taxonomy": ["network", "parser_drift", "timeout", "policy"],
            "fallbacks": [],
            "cleanup": {
                "receipt_owned_only": True,
                "preserve_artifacts": True,
                "remove_external_dependencies": False,
            },
            "owner": "tools-evm",
            "last_verified": VERIFIED,
            "provenance": [_provenance(PRV_SOLODIT, "solodit.search", "api-v1")],
        }
    )


def all_manifests() -> dict[str, dict[str, Any]]:
    return {
        "solc": solc_manifest(),
        "foundry": foundry_manifest(),
        "slither": slither_manifest(),
        "solodit": solodit_manifest(),
    }
