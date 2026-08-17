import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { activate, createRuntime } from "../../prime/extension/index.ts";
import type {
  ExtensionAPI,
  ExtensionCommandContext,
  HookHandler,
  RegisteredCommandOptions,
} from "../../prime/extension/prime-api.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

interface MockPi extends ExtensionAPI {
  handlers: Map<string, HookHandler[]>;
  commands: Map<string, RegisteredCommandOptions>;
  entries: Array<{ customType: string; data?: unknown }>;
  fire(event: string, payload?: Record<string, unknown>): Promise<unknown[]>;
}

function mockCtx(): ExtensionCommandContext {
  return {
    ui: { notify() {} },
    hasUI: false,
    cwd: root,
    sessionManager: {},
    shutdown() {},
    getSystemPrompt() {
      return "";
    },
    waitForIdle: async () => undefined,
  };
}

function mockPi(): MockPi {
  const handlers = new Map<string, HookHandler[]>();
  const commands = new Map<string, RegisteredCommandOptions>();
  const entries: Array<{ customType: string; data?: unknown }> = [];
  const ctx = mockCtx();
  const api: MockPi = {
    handlers,
    commands,
    entries,
    on(event, handler) {
      const list = handlers.get(event) ?? [];
      list.push(handler);
      handlers.set(event, list);
    },
    registerCommand(name, options) {
      commands.set(name, options);
    },
    registerFlag() {},
    getFlag() {
      return false;
    },
    sendMessage() {},
    appendEntry(customType, data) {
      entries.push({ customType, data });
    },
    async fire(event, payload = {}) {
      const list = handlers.get(event) ?? [];
      const results: unknown[] = [];
      for (const handler of list) {
        results.push(await handler(payload, ctx));
      }
      return results;
    },
  };
  return api;
}

test("--ayran flag arms the session", () => {
  const pi = mockPi();
  pi.getFlag = (name) => name === "ayran";
  const runtime = createRuntime(root);
  activate(pi, root, runtime);
  assert.equal(runtime.sessionActive, true);
});

test("idle session_start does not spawn sidecar", async () => {
  const pi = mockPi();
  const runtime = createRuntime(root);
  activate(pi, root, runtime);
  await pi.fire("session_start", { reason: "startup" });
  assert.equal(runtime.sessionActive, false);
  assert.equal(runtime.sidecarProcess, undefined);
  assert.equal(runtime.spawnedSidecar, false);
});

test("idle session does not inject context or fail-close tools", async () => {
  const pi = mockPi();
  const runtime = createRuntime(root);
  activate(pi, root, runtime);
  assert.equal(runtime.sessionActive, false);
  const injected = await pi.fire("before_agent_start", { prompt: "hello" });
  assert.equal(injected[0], undefined);
  const tools = (await pi.fire("tool_call", {
    toolName: "read",
    input: { path: "target/src/Vault.sol" },
  })) as Array<{ block?: boolean } | undefined>;
  assert.equal(tools[0], undefined);
});

test("armed session without sidecar injects a degraded pack and fail-closes tools", async () => {
  const pi = mockPi();
  const runtime = createRuntime(root);
  runtime.sessionActive = true;
  runtime.autoStartSidecar = false;
  activate(pi, root, runtime);
  const results = await pi.fire("before_agent_start", { prompt: "hello" });
  const injected = results[0] as {
    message?: { content?: string; customType?: string };
  };
  assert.equal(injected.message?.customType, "ayran.context_pack");
  assert.match(String(injected.message?.content), /unavailable/i);
  const blocked = (await pi.fire("tool_call", {
    toolName: "read",
    input: { path: "target/src/Vault.sol" },
  })) as Array<{ block?: boolean }>;
  assert.equal(blocked[0]?.block, true);
});

test("hook registration has no duplicate handlers", () => {
  const pi = mockPi();
  activate(pi, root, createRuntime(root));
  for (const [event, handlers] of pi.handlers) {
    assert.equal(handlers.length, 1, event);
  }
  assert.ok(pi.handlers.has("before_agent_start"));
  assert.ok(pi.handlers.has("tool_call"));
  assert.ok(pi.handlers.has("session_compact"));
  assert.ok(pi.handlers.has("session_shutdown"));
});

test("degraded sidecar fail-closes mapped tool calls when armed", async () => {
  const pi = mockPi();
  const runtime = createRuntime(root);
  runtime.sessionActive = true;
  runtime.autoStartSidecar = false;
  activate(pi, root, runtime);
  const blocked = (await pi.fire("tool_call", {
    toolName: "read",
    input: { path: "target/src/Vault.sol" },
  })) as Array<{ block?: boolean }>;
  assert.equal(blocked[0]?.block, true);
});

test("ipython disallowed payloads are blocked with a not-a-sandbox warning", async () => {
  const pi = mockPi();
  const runtime = createRuntime(root);
  runtime.sessionActive = true;
  runtime.autoStartSidecar = false;
  runtime.sidecar.tryCall = async () => ({ permitted: true, routed: false });
  activate(pi, root, runtime);
  const blocked = (await pi.fire("tool_call", {
    toolName: "ipython",
    input: { code: "import subprocess\nsubprocess.run(['id'])" },
  })) as Array<{ block?: boolean; reason?: string }>;
  assert.equal(blocked[0]?.block, true);
  assert.match(String(blocked[0]?.reason), /not a sandbox/i);
});

test("policy gate rejects denied tools and passes allowed tools", async () => {
  const pi = mockPi();
  const runtime = createRuntime(root);
  runtime.sessionActive = true;
  runtime.autoStartSidecar = false;
  runtime.sidecar.tryCall = async (method, params = {}) => {
    if (method !== "policy.authorize") {
      return { ok: true };
    }
    const tool = String(params.tool_name ?? "");
    const path = String(
      (params.arguments as { path?: string } | undefined)?.path ?? "",
    );
    if (path.startsWith("secrets/") || tool === "bash") {
      return { permitted: false, reason: "out of scope", routed: false };
    }
    return { permitted: true, routed: false };
  };
  activate(pi, root, runtime);
  const denied = (await pi.fire("tool_call", {
    toolName: "read",
    input: { path: "secrets/key.sol" },
  })) as Array<{ block?: boolean }>;
  const allowed = (await pi.fire("tool_call", {
    toolName: "read",
    input: { path: "target/src/Vault.sol" },
  })) as Array<{ block?: boolean } | undefined>;
  assert.equal(denied[0]?.block, true);
  assert.equal(allowed[0], undefined);
});

test("session switch fork and compact re-inject without crashing", async () => {
  const pi = mockPi();
  const runtime = createRuntime(root);
  runtime.sessionActive = true;
  runtime.autoStartSidecar = false;
  const calls: string[] = [];
  runtime.sidecar.tryCall = async (method) => {
    calls.push(method);
    if (method === "context.compile" || method === "context.pack") {
      return {
        reconstruction_ok: true,
        content_hash: "sha256:" + "ab".repeat(32),
        pack: {
          sections: [
            { title: "Active hypothesis", content: "h" },
            { title: "Result so far", content: "r" },
            { title: "Next action", content: "n" },
            { title: "Dead approaches", content: "d" },
            { title: "Untried dimensions", content: "u" },
          ],
        },
      };
    }
    return { ok: true, checkpoint_id: "chk_test" };
  };
  activate(pi, root, runtime);
  await pi.fire("session_start", { reason: "fork" });
  await pi.fire("session_before_compact", { preparation: { tokensBefore: 1 } });
  await pi.fire("session_compact", { compactionEntry: { id: "c1" } });
  await pi.fire("session_before_switch", { reason: "new" });
  await pi.fire("session_before_fork", {});
  const injected = (await pi.fire("before_agent_start", {
    prompt: "go",
  })) as Array<{
    message?: { content?: string };
  }>;
  assert.match(String(injected[0]?.message?.content), /Active hypothesis/);
  assert.ok(calls.includes("context.compile"));
  assert.ok(calls.includes("lifecycle.record"));
});

test("command surface is self-documenting", async () => {
  const pi = mockPi();
  const runtime = createRuntime(root);
  runtime.sessionActive = true;
  runtime.autoStartSidecar = false;
  runtime.sidecar.tryCall = async (method) => ({
    method,
    sidecar: "reachable",
  });
  activate(pi, root, runtime);
  for (const name of [
    "ayran:status",
    "ayran:doctor",
    "ayran:stop",
    "ayran:recover",
  ]) {
    const command = pi.commands.get(name);
    assert.ok(command, name);
    assert.ok(command.description && command.description.length > 8, name);
    await command.handler("", mockCtx());
  }
});

test("repeated start and shutdown is clean ten times", async () => {
  for (let index = 0; index < 10; index += 1) {
    const pi = mockPi();
    const runtime = createRuntime(root);
    runtime.sessionActive = true;
    runtime.autoStartSidecar = false;
    runtime.sidecar.call = async () => ({ run_state: "stopped" });
    runtime.sidecar.tryCall = async () => ({ ok: true });
    activate(pi, root, runtime);
    await pi.fire("session_start", { reason: "startup" });
    await pi.fire("session_shutdown", { reason: "quit" });
    assert.equal(runtime.closed, true);
  }
});
