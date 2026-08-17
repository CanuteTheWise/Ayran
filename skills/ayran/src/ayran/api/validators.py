"""Offline canonical-schema, Pydantic, context, and integrity validation."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import BaseModel, TypeAdapter
from referencing import Registry, Resource

from . import models

ROOT = Path(__file__).resolve().parents[5]
SCHEMA_ROOT = ROOT / "schemas"
CATALOG = json.loads((SCHEMA_ROOT / "catalog.json").read_text(encoding="utf-8"))
CONTRACTS = {item["name"]: item for item in CATALOG["contracts"]}
SCHEMAS = {
    name: json.loads((SCHEMA_ROOT / item["schema"]).read_text(encoding="utf-8"))
    for name, item in CONTRACTS.items()
}
REGISTRY = Registry()
for schema in SCHEMAS.values():
    REGISTRY = REGISTRY.with_resource(schema["$id"], Resource.from_contents(schema))
VALIDATORS = {
    name: Draft202012Validator(schema, registry=REGISTRY, format_checker=FormatChecker())
    for name, schema in SCHEMAS.items()
}


class ContractValidationError(ValueError):
    """A contract failed a canonical, contextual, Pydantic, or integrity rule."""


def _without_integrity(value: Any) -> Any:
    clone = copy.deepcopy(value)
    if isinstance(clone, dict):
        integrity = clone.get("integrity")
        if isinstance(integrity, dict):
            integrity.pop("content_hash", None)
        clone.pop("event_hash", None)
    return clone


def canonical_hash(value: Any) -> str:
    try:
        encoded = rfc8785.dumps(_without_integrity(value))
    except (TypeError, ValueError) as error:
        raise ContractValidationError(f"value is not RFC 8785 canonicalizable: {error}") from error
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _contextual_errors(
    name: str, value: dict[str, Any], context: dict[str, str] | None
) -> list[str]:
    errors: list[str] = []
    if context and context.get("run_id") and value.get("run_id") != context["run_id"]:
        errors.append("run_id does not match contract context")
    target = value.get("target_identity")
    if (
        context
        and context.get("target_id")
        and "target_identity" in value
        and (not isinstance(target, dict) or target.get("target_id") != context["target_id"])
    ):
        errors.append("target_id does not match contract context")
    if name == "scope-manifest":
        seen: dict[tuple[str, str], str] = {}
        for rule in value.get("rules", []):
            key = (rule.get("action", ""), rule.get("resource", ""))
            if key in seen and seen[key] != rule.get("effect"):
                errors.append("ambiguous allow/deny rule pair")
            seen[key] = rule.get("effect", "")
    if name == "graph-event":
        if value.get("seq") == 1 and value.get("previous_event_hash") is not None:
            errors.append("genesis event must have null previous_event_hash")
        if (
            isinstance(value.get("seq"), int)
            and value["seq"] > 1
            and value.get("previous_event_hash") is None
        ):
            errors.append("non-genesis event requires previous_event_hash")
    if (
        name == "evidence-artifact"
        and value.get("evidence_grade") == "validated"
        and value.get("trust_class")
        in {"model_observation", "model_assumption", "curated_external"}
    ):
        errors.append("model or historical material cannot be validated evidence")
    integrity = value.get("integrity")
    if isinstance(integrity, dict):
        expected_exclusions = {
            "integrity.content_hash",
            *( ["event_hash"] if name in {"graph-event", "journal-event"} else [] ),
        }
        if set(integrity.get("excluded_fields", [])) != expected_exclusions:
            errors.append("integrity.excluded_fields does not match the contract hash rules")
    actual_hash = canonical_hash(value) if isinstance(integrity, dict) else None
    if isinstance(integrity, dict) and integrity.get("content_hash") != actual_hash:
        errors.append("integrity.content_hash does not match RFC 8785 canonical content")
    if name in {"graph-event", "journal-event"} and value.get("event_hash") != actual_hash:
        errors.append("event_hash does not match canonical event content")
    return errors


def validate_contract(name: str, value: Any, context: dict[str, str] | None = None) -> None:
    if name not in CONTRACTS:
        raise KeyError(f"Unknown contract: {name}")
    validator = VALIDATORS[name]
    errors = [
        f"{list(error.absolute_path)}: {error.message}" for error in validator.iter_errors(value)
    ]
    if not errors and isinstance(value, dict):
        errors.extend(_contextual_errors(name, value, context))
    if errors:
        raise ContractValidationError("; ".join(errors))


def parse_contract(name: str, value: Any, context: dict[str, str] | None = None) -> Any:
    validate_contract(name, value, context)
    model_type = getattr(models, CONTRACTS[name]["python_model"])
    if isinstance(model_type, type) and issubclass(model_type, BaseModel):
        return model_type.model_validate(value)

    return TypeAdapter(model_type).validate_python(value)
