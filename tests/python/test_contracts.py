from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from ayran.api.validators import (
    CONTRACTS,
    REGISTRY,
    SCHEMAS,
    ContractValidationError,
    canonical_hash,
    parse_contract,
    validate_contract,
)
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "fixtures" / "contracts"
MANIFEST = json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8"))


def load(row: dict[str, Any]) -> Any:
    return json.loads((FIXTURE_ROOT / row["path"]).read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "row",
    [row for row in MANIFEST["fixtures"] if row["expected"] == "valid"],
    ids=lambda row: row["path"],
)
def test_valid_fixture_parity_and_round_trip(row: dict[str, Any]) -> None:
    value = load(row)
    validate_contract(row["contract"], value, row.get("context"))
    model = parse_contract(row["contract"], value, row.get("context"))
    assert json.loads(json.dumps(value, separators=(",", ":"))) == value
    assert model.__class__.model_validate_json(json.dumps(value)) == model
    if "integrity" in value:
        assert value["integrity"]["content_hash"] == canonical_hash(value)
    if row["contract"] == "graph-event":
        assert value["event_hash"] == canonical_hash(value)


@pytest.mark.parametrize(
    "row",
    [row for row in MANIFEST["fixtures"] if row["expected"] == "invalid"],
    ids=lambda row: row["path"],
)
def test_invalid_fixtures_fail_canonical_and_pydantic_boundary(row: dict[str, Any]) -> None:
    with pytest.raises(ContractValidationError):
        parse_contract(row["contract"], load(row), row.get("context"))


def test_all_catalog_contracts_have_minimum_full_and_multiple_invalid_fixtures() -> None:
    for name in CONTRACTS:
        rows = [row for row in MANIFEST["fixtures"] if row["contract"] == name]
        assert {row.get("variant") for row in rows if row["expected"] == "valid"} == {
            "minimal",
            "full",
        }
        assert len([row for row in rows if row["expected"] == "invalid"]) >= 3


def test_schemas_are_draft_2020_12_and_resolve_offline() -> None:
    ids: set[str] = set()
    for name, schema in SCHEMAS.items():
        Draft202012Validator.check_schema(schema)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"] not in ids
        ids.add(schema["$id"])
        Draft202012Validator(schema, registry=REGISTRY)
        assert name in CONTRACTS


def test_schema_security_vocabulary_is_separate() -> None:
    common = SCHEMAS["common"]["$defs"]
    assert set(common["HypothesisOrigin"]["enum"]) == {
        "model_novel",
        "global_graph",
        "contradiction",
        "tool",
        "coverage",
        "specialist",
    }
    assert set(common["EvidenceGrade"]["enum"]) == {
        "lead",
        "supported",
        "observed",
        "defect_pinned",
        "validated",
    }
    assert "model_observation" in common["TrustClass"]["enum"]
    assert common["Confidence"]["minimum"] == 0 and common["Confidence"]["maximum"] == 1


def test_no_secret_value_or_autonomous_external_action_field() -> None:
    forbidden = {
        "private_key",
        "secret_value",
        "raw_secret",
        "signing_key",
        "broadcast_transaction",
        "submit_finding",
        "autonomous_promotion",
    }
    for schema in SCHEMAS.values():
        text = json.dumps(schema).lower()
        for field in forbidden:
            assert f'"{field}"' not in text
