import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

function readPiManifest(packageRoot: string): {
  extensions?: string[];
  skills?: string[];
  prompts?: string[];
  themes?: string[];
} | null {
  try {
    const pkg = JSON.parse(
      readFileSync(join(packageRoot, "package.json"), "utf8"),
    ) as {
      pi?: {
        extensions?: string[];
        skills?: string[];
        prompts?: string[];
        themes?: string[];
      };
    };
    return pkg.pi ?? null;
  } catch {
    return null;
  }
}

test("stock Prime 0.7.2 readPiManifest discovers Ayran resources", () => {
  const pi = readPiManifest(root);
  assert.ok(pi);
  assert.deepEqual(pi.extensions, ["./prime/extension/index.ts"]);
  assert.deepEqual(pi.skills, ["./skills/ayran", "./skills/specialists"]);
  assert.deepEqual(pi.prompts, ["./prime/prompts"]);
  for (const relative of [
    ...(pi.extensions ?? []),
    ...(pi.skills ?? []),
    ...(pi.prompts ?? []),
  ]) {
    assert.equal(existsSync(resolve(root, relative)), true, relative);
  }
});

test("pinned Prime 0.7.2 documents the mapped lifecycle events", () => {
  const docs = join(root, "var/prime-0.7.2-inspect/package/docs/extensions.md");
  if (!existsSync(docs)) {
    return;
  }
  const text = readFileSync(docs, "utf8");
  for (const event of [
    "before_agent_start",
    "tool_call",
    "session_before_compact",
    "session_compact",
    "session_before_switch",
    "session_before_fork",
    "session_shutdown",
    "session_start",
  ]) {
    assert.match(text, new RegExp(event));
  }
});
