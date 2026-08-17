# Schema generation

JSON Schema Draft 2020-12 files under `schemas/` are the only authored cross-language contract source. `schemas/catalog.json` maps stable contract names to canonical schema entrypoints and generated Pydantic classes.

Generation is version-locked to `datamodel-code-generator==0.72.3` for Pydantic v2 and `json-schema-to-typescript==15.0.4` for TypeScript. Ajv `8.20.0` always validates the canonical schemas; TypeScript interfaces do not replace runtime validation.

Run `uv run python scripts/generate_contracts.py` to generate and `uv run python scripts/generate_contracts.py --check` to verify. The generator strips timestamps and host paths, uses strict Pydantic scalar types with unknown fields forbidden, embeds the schema registry for offline Ajv validation, and emits an RFC 8785/SHA-256 helper.

Cross-object semantics that Draft 2020-12 cannot express—target/run binding, genesis predecessor rules, allow/deny ambiguity, and historical/model evidence ceilings—are enforced by generated validation support and shared fixtures.
