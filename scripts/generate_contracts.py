"""Generate deterministic Pydantic v2 and TypeScript/Ajv contract artifacts."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
PYTHON_OUT = ROOT / "skills" / "ayran" / "src" / "ayran" / "api"
TS_OUT = ROOT / "prime" / "extension" / "generated"


def executable(name: str) -> str:
    suffix = ".exe" if sys.platform == "win32" else ""
    local = ROOT / ".venv" / ("Scripts" if sys.platform == "win32" else "bin") / f"{name}{suffix}"
    return str(local) if local.exists() else name


def node_executable(name: str) -> str:
    suffix = ".cmd" if sys.platform == "win32" else ""
    local = ROOT / "node_modules" / ".bin" / f"{name}{suffix}"
    return str(local) if local.exists() else name


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def format_typescript(content: str) -> bytes:
    result = subprocess.run(
        [node_executable("prettier"), "--parser", "typescript"],
        cwd=ROOT,
        check=True,
        input=content.encode(),
        stdout=subprocess.PIPE,
    )
    return result.stdout


def python_models(work: Path) -> dict[Path, bytes]:
    modular = work / "python"
    run(
        [
            executable("datamodel-codegen"),
            "--input",
            str(SCHEMAS / "contracts.schema.json"),
            "--input-file-type",
            "jsonschema",
            "--output",
            str(modular),
            "--output-model-type",
            "pydantic_v2.BaseModel",
            "--target-python-version",
            "3.11",
            "--extra-fields",
            "forbid",
            "--field-constraints",
            "--use-annotated",
            "--use-union-operator",
            "--use-standard-collections",
            "--enum-field-as-literal",
            "all",
            "--strict-types",
            "str",
            "bytes",
            "int",
            "float",
            "bool",
            "--disable-timestamp",
            "--use-title-as-name",
            "--formatters",
            "black",
            "isort",
        ]
    )
    models = (modular / "__init__.py").read_text(encoding="utf-8")
    models = models.replace("from ._internal import", "from ._models_internal import")
    models = models.replace(
        "#   filename:  contracts.schema.json",
        "#   canonical source: schemas/contracts.schema.json",
    )
    models += (
        "\nfrom ._models_internal import Schema_1 as JournalRecord\n\n"
        "Finding = FindingCandidate | ValidatedFinding\n"
        "LearningOutcome = QuarantinedLearningOutcome | EvaluatedLearningOutcome | ReleasedLearningOutcome\n"
        "__all__ += ['Finding', 'JournalRecord', 'LearningOutcome']\n"
    )
    internal = (modular / "_internal.py").read_text(encoding="utf-8")
    internal = internal.replace(
        "#   filename:  _internal", "#   canonical source: schemas/contracts.schema.json"
    )
    return {
        PYTHON_OUT / "models.py": models.encode(),
        PYTHON_OUT / "_models_internal.py": internal.encode(),
    }


def typescript_types(work: Path) -> dict[Path, bytes]:
    output = work / "contracts.ts"
    run(
        [
            node_executable("json2ts"),
            "-i",
            str(SCHEMAS / "contracts.schema.json"),
            "-o",
            str(output),
            "--cwd",
            str(SCHEMAS),
            "--unreachableDefinitions",
            "true",
        ]
    )
    types = output.read_text(encoding="utf-8").replace("\r\n", "\n")
    return {
        TS_OUT / "contracts.ts": format_typescript(
            "// Canonical source: schemas/contracts.schema.json\n" + types
        )
    }


VALIDATOR_TEMPLATE = r"""// Generated from schemas/catalog.json and schemas/*.schema.json. Do not edit.
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormatsImport from "ajv-formats";
import type { ErrorObject } from "ajv";
import canonicalize from "canonicalize";
import { createHash } from "node:crypto";

export const schemas = __SCHEMAS__ as const;
export type ContractName = keyof typeof schemas;
export interface ContractContext { run_id?: string; target_id?: string }
export interface ValidationResult { valid: boolean; errors: string[] }

const ajv = new Ajv2020({ strict: true, allowUnionTypes: true, allErrors: true, validateFormats: true, coerceTypes: false, useDefaults: false, removeAdditional: false });
const addFormats = addFormatsImport as unknown as (instance: Ajv2020) => Ajv2020;
addFormats(ajv);
ajv.addKeyword({ keyword: "x-ayran-schema-version", schemaType: "string", valid: true });
for (const schema of Object.values(schemas)) ajv.addSchema(schema);

function cloneWithoutIntegrity(value: unknown): unknown {
  const clone = structuredClone(value) as Record<string, unknown>;
  if (clone && typeof clone === "object") {
    if (clone.integrity && typeof clone.integrity === "object") delete (clone.integrity as Record<string, unknown>).content_hash;
    delete clone.event_hash;
  }
  return clone;
}

export function canonicalHash(value: unknown): string {
  const encoded = canonicalize(cloneWithoutIntegrity(value));
  if (encoded === undefined) throw new Error("Value is not JSON-canonicalizable");
  return `sha256:${createHash("sha256").update(encoded, "utf8").digest("hex")}`;
}

function contextualErrors(name: ContractName, value: Record<string, unknown>, context?: ContractContext): string[] {
  const errors: string[] = [];
  if (context?.run_id && value.run_id !== context.run_id) errors.push("run_id does not match contract context");
  const target = value.target_identity as Record<string, unknown> | undefined;
  if (context?.target_id && target?.target_id !== context.target_id) errors.push("target_id does not match contract context");
  if (name === "scope-manifest") {
    const seen = new Map<string, string>();
    for (const rule of (value.rules as Array<Record<string, string>> | undefined) ?? []) {
      const key = `${rule.action}\u0000${rule.resource}`;
      if (seen.has(key) && seen.get(key) !== rule.effect) errors.push("ambiguous allow/deny rule pair");
      seen.set(key, rule.effect);
    }
  }
  if (name === "graph-event") {
    if (value.seq === 1 && value.previous_event_hash !== null) errors.push("genesis event must have null previous_event_hash");
    if (typeof value.seq === "number" && value.seq > 1 && value.previous_event_hash === null) errors.push("non-genesis event requires previous_event_hash");
  }
  if (name === "evidence-artifact" && value.evidence_grade === "validated" && ["model_observation", "model_assumption", "curated_external"].includes(String(value.trust_class))) errors.push("model or historical material cannot be validated evidence");
  const integrity = value.integrity as Record<string, unknown> | undefined;
  if (integrity) {
    const expected = new Set(name === "graph-event" || name === "journal-event" ? ["integrity.content_hash", "event_hash"] : ["integrity.content_hash"]);
    const actual = new Set((integrity.excluded_fields as string[] | undefined) ?? []);
    if (actual.size !== expected.size || [...actual].some((item) => !expected.has(item))) errors.push("integrity.excluded_fields does not match the contract hash rules");
  }
  if (integrity?.content_hash && integrity.content_hash !== canonicalHash(value)) errors.push("integrity.content_hash does not match RFC 8785 canonical content");
  if ((name === "graph-event" || name === "journal-event") && value.event_hash !== canonicalHash(value)) errors.push("event_hash does not match canonical event content");
  return errors;
}

export function validateContract(name: ContractName, value: unknown, context?: ContractContext): ValidationResult {
  const schema = schemas[name];
  const validate = ajv.getSchema(schema.$id) ?? ajv.compile(schema);
  const valid = validate(value);
  const errors = valid ? [] : (validate.errors ?? []).map((e: ErrorObject) => `${e.instancePath || "/"} ${e.message ?? "invalid"}`);
  if (valid && value && typeof value === "object") errors.push(...contextualErrors(name, value as Record<string, unknown>, context));
  return { valid: errors.length === 0, errors };
}
"""


def typescript_validators() -> dict[Path, bytes]:
    catalog = json.loads((SCHEMAS / "catalog.json").read_text(encoding="utf-8"))
    schemas = {
        item["name"]: json.loads((SCHEMAS / item["schema"]).read_text(encoding="utf-8"))
        for item in catalog["contracts"]
    }
    embedded = json.dumps(schemas, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        TS_OUT / "validators.ts": format_typescript(
            VALIDATOR_TEMPLATE.replace("__SCHEMAS__", embedded)
        )
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ayran-contracts-") as temp:
        work = Path(temp)
        generated = python_models(work) | typescript_types(work) | typescript_validators()
    stale: list[str] = []
    for path, content in generated.items():
        if args.check:
            if not path.exists() or path.read_bytes() != content:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    if stale:
        print("Generated contracts are stale: " + ", ".join(stale), file=sys.stderr)
        return 1
    print(f"{'Verified' if args.check else 'Generated'} {len(generated)} contract artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
