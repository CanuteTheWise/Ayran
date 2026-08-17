import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  canonicalHash,
  validateContract,
  type ContractName,
} from "../../prime/extension/generated/validators.js";

interface FixtureRow {
  contract: ContractName;
  path: string;
  expected: "valid" | "invalid";
  context?: { run_id?: string; target_id?: string };
}

const root = new URL("../../fixtures/contracts/", import.meta.url);
const manifest = JSON.parse(
  await readFile(new URL("manifest.json", root), "utf8"),
) as { fixtures: FixtureRow[] };

for (const row of manifest.fixtures) {
  test(`${row.expected}: ${row.path}`, async () => {
    const value = JSON.parse(
      await readFile(new URL(row.path, root), "utf8"),
    ) as Record<string, unknown>;
    const result = validateContract(row.contract, value, row.context);
    assert.equal(
      result.valid,
      row.expected === "valid",
      result.errors.join("; "),
    );
    if (row.expected === "valid") {
      const roundTrip = JSON.parse(JSON.stringify(value)) as Record<
        string,
        unknown
      >;
      assert.deepEqual(roundTrip, value);
      if (value.integrity && typeof value.integrity === "object") {
        assert.equal(
          (value.integrity as Record<string, unknown>).content_hash,
          canonicalHash(value),
        );
      }
      if (row.contract === "graph-event")
        assert.equal(value.event_hash, canonicalHash(value));
    }
  });
}
