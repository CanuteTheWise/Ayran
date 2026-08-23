import { detectKernel, type RuntimeState } from "./bootstrap.ts";
import { deliverChildCredential } from "./credentials.ts";
import {
  ensureSidecar,
  resolveScopeManifest,
  stopSpawnedSidecar,
} from "./launch.ts";
import type {
  CustomMessage,
  ExtensionAPI,
  ExtensionContext,
  HookHandler,
} from "./prime-api.ts";
import { sha256Hex } from "./telemetry.ts";

const CONTEXT_TYPE = "ayran.context_pack";
const EMPTY_NOTE =
  "Graph state is unavailable. The Ayran sidecar could not be reached. Continue without injected Target Graph context.";

interface PackResult {
  pack?: {
    sections?: Array<{
      title: string;
      content: string;
      classification?: string;
    }>;
  };
  injection_text?: string;
  reconstruction_ok?: boolean;
  content_hash?: string;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object"
    ? (value as Record<string, unknown>)
    : {};
}

function packContent(
  runtime: RuntimeState,
  pack: PackResult | undefined,
  degraded: boolean,
): string {
  const header = runtime.settings.contextPackHeader.trimEnd();
  if (degraded || (!pack?.pack && !pack?.injection_text)) {
    return `${header}\n\n${EMPTY_NOTE}\n`;
  }
  if (pack.injection_text) {
    return `${header}\n\n${pack.injection_text}`;
  }
  const sections = pack.pack?.sections ?? [];
  const body = sections
    .map((section) => {
      const label = section.classification
        ? `[${section.classification}] `
        : "";
      return `## ${label}${section.title}\n\n${section.content}`;
    })
    .join("\n\n");
  return `${header}\n\n${body}\n`;
}

async function injectPack(runtime: RuntimeState): Promise<CustomMessage> {
  const result = (await runtime.sidecar.tryCall("context.compile", {
    token_budget: runtime.settings.contextPackTokenBudget,
    purpose: "audit-turn",
    role: "root-auditor",
  })) as PackResult | undefined;
  const degraded = result === undefined;
  if (degraded) {
    runtime.telemetry.event("warn", "ayran.context.sidecar_unreachable", {
      outcome: "degraded",
    });
  } else {
    runtime.lastPackHash =
      typeof result.content_hash === "string" ? result.content_hash : undefined;
    runtime.telemetry.event("info", "ayran.context.injected", {
      content_hash: runtime.lastPackHash,
      reconstruction_ok: Boolean(result.reconstruction_ok),
    });
  }
  return {
    customType: CONTEXT_TYPE,
    content: packContent(runtime, result, degraded),
    display: false,
    details: {
      content_hash: runtime.lastPackHash,
      degraded,
    },
  };
}

function extractHandle(value: unknown): Record<string, unknown> | undefined {
  const record = asRecord(value);
  if (
    typeof record.rlm_child_id === "string" ||
    typeof record.child_id === "string"
  ) {
    return record;
  }
  const nested = record.handle;
  if (nested && typeof nested === "object") {
    const handle = asRecord(nested);
    if (
      typeof handle.rlm_child_id === "string" ||
      typeof handle.child_id === "string"
    ) {
      return handle;
    }
  }
  if (typeof value === "string" && value.includes("rlm_child_id")) {
    const match = value.match(/\{[\s\S]*"rlm_child_id"[\s\S]*\}/);
    if (match) {
      try {
        return asRecord(JSON.parse(match[0]));
      } catch {
        return undefined;
      }
    }
  }
  return undefined;
}

function armFromFlag(pi: ExtensionAPI, runtime: RuntimeState): void {
  if (
    !runtime.sessionActive &&
    typeof pi.getFlag === "function" &&
    pi.getFlag("ayran")
  ) {
    runtime.sessionActive = true;
  }
}

export function registerHooks(
  pi: ExtensionAPI,
  runtime: RuntimeState,
): string[] {
  const registered: string[] = [];
  const seen = new Set<string>();

  const on = (event: string, handler: HookHandler): void => {
    if (seen.has(event)) {
      return;
    }
    if (!runtime.settings.enabledHooks.includes(event)) {
      return;
    }
    seen.add(event);
    pi.on(event, handler);
    registered.push(event);
  };

  on("session_start", async (event) => {
    runtime.lastSessionReason = String(event.reason ?? "startup");
    armFromFlag(pi, runtime);
    if (runtime.sessionActive) {
      if (typeof pi.getFlag === "function") {
        const flagged = pi.getFlag("ayran-manifest");
        if (typeof flagged === "string" && flagged.trim()) {
          runtime.scopeManifestPath = flagged.trim();
        }
      }
      const cwd = String(event.cwd ?? process.cwd());
      runtime.scopeManifestPath = resolveScopeManifest(
        cwd,
        runtime.scopeManifestPath,
      );
      await ensureSidecar(runtime, cwd);
    }
    if (!runtime.sessionActive) {
      return;
    }
    await detectKernel(runtime);
    const status = await runtime.sidecar.tryCall("run.status");
    if (status === undefined) {
      runtime.telemetry.event("warn", "ayran.session.start.degraded", {
        reason: runtime.lastSessionReason,
        outcome: "degraded",
      });
      return;
    }
    const record = asRecord(status);
    pi.appendEntry("ayran.run_binding", {
      run_id: record.run_id ?? runtime.settings.runId,
      checkpoint_id: asRecord(record.receipt).checkpoint_id,
      graph_cursor:
        asRecord(record.receipt).graph_cursor ??
        asRecord(record.run).graph_cursor,
    });
    if (
      runtime.lastSessionReason === "new" ||
      runtime.lastSessionReason === "resume" ||
      runtime.lastSessionReason === "fork"
    ) {
      await runtime.sidecar.tryCall("lifecycle.record", {
        event_type: `session_start.${runtime.lastSessionReason}`,
        payload: { reason: runtime.lastSessionReason, session_id: "omitted" },
      });
    }
  });

  on("resources_discover", async () => {
    // Stock Prime 0.7.2 contract expects an object (skillPaths?/promptPaths?/
    // themePaths?), not undefined; a well-formed empty catalog is the honest
    // answer while Ayran surfaces its resources through skills, not here.
    return {};
  });

  on("before_agent_start", async () => {
    armFromFlag(pi, runtime);
    if (!runtime.sessionActive || !runtime.injectionActive) {
      return undefined;
    }
    try {
      return { message: await injectPack(runtime) };
    } catch (error) {
      runtime.telemetry.event("error", "ayran.context.inject_failed", {
        outcome: "degraded",
        error_class: error instanceof Error ? error.name : "unknown",
      });
      return {
        message: {
          customType: CONTEXT_TYPE,
          content: packContent(runtime, undefined, true),
          display: false,
        },
      };
    }
  });

  on("context", (event) => {
    const messages = Array.isArray(event.messages) ? [...event.messages] : [];
    let last = -1;
    for (let index = 0; index < messages.length; index += 1) {
      const message = asRecord(messages[index]);
      if (message.customType === CONTEXT_TYPE) {
        last = index;
      }
    }
    if (last < 0) {
      return undefined;
    }
    return {
      messages: messages.filter((item, index) => {
        const message = asRecord(item);
        return message.customType !== CONTEXT_TYPE || index === last;
      }),
    };
  });

  on("tool_call", async (event) => {
    armFromFlag(pi, runtime);
    if (!runtime.sessionActive) {
      return undefined;
    }
    const toolName = String(event.toolName ?? "");
    const input = asRecord(event.input);
    // Native tool flow (§7.2 row 1): approved calls are never intercepted —
    // they proceed through the stock Prime tool machinery; deny still wins.
    // ipython payloads are NOT string-sniffed (§7.2 row 2): enforcement is
    // the single-writer sidecar boundary + scope + verb ACLs at the RPC
    // boundary. This hook itself contains no local-execution path.
    //
    // CONTINGENCY CLAUSE (§7.2): this ordering assumes the stock Prime 0.7.2+
    // tool_call hook fires PRE-execution, so a denial below precedes any byte
    // read or written. If live verification ever disproves PRE-execution
    // ordering in a current or future Prime version, routed interception is
    // reinstated for bash/write tools only (fail-closed).
    const decision = (await runtime.sidecar.tryCall("policy.authorize", {
      tool_name: toolName,
      arguments: input,
    })) as
      | {
          permitted?: boolean;
          reason?: string;
        }
      | undefined;
    if (decision === undefined) {
      runtime.telemetry.event("warn", "ayran.tool.policy_unavailable", {
        outcome: "blocked",
        tool_name_hash: sha256Hex(toolName),
      });
      return {
        block: true,
        reason:
          "Ayran policy sidecar is unreachable; fail closed. This is policy gating, not OS sandboxing.",
      };
    }
    if (!decision.permitted) {
      return {
        block: true,
        reason: decision.reason ?? "tool call denied by Ayran scope policy",
      };
    }
    return undefined;
  });

  on("tool_result", async (event) => {
    if (!runtime.sessionActive) {
      return undefined;
    }
    if (String(event.toolName ?? "") !== "ipython") {
      return undefined;
    }
    const handle = extractHandle(event.details) ?? extractHandle(event.content);
    if (handle) {
      await runtime.sidecar.tryCall("child.register", { handle });
      // §11.4/W7: on observing a child, mint the child-bound
      // gate_a_submission token extension-side and vault it server-side; the
      // model never handles a challenger token.
      const childId = String(handle.rlm_child_id ?? handle.child_id ?? "");
      await deliverChildCredential(runtime, childId);
    }
    return undefined;
  });

  on("message_end", async (event) => {
    if (!runtime.sessionActive) {
      return undefined;
    }
    const message = asRecord(event.message ?? event);
    if (message.customType === "rlm_child_failure") {
      await runtime.sidecar.tryCall("child.fail", {
        handle: extractHandle(message.details) ?? {
          rlm_child_id: String(message.content ?? "unknown"),
        },
        error: String(message.content ?? "child failed"),
      });
    }
    if (message.customType === "rlm_child_terminal_notice") {
      const handle =
        extractHandle(message.details) ??
        ({ rlm_child_id: String(message.content ?? "unknown") } as Record<
          string,
          unknown
        >);
      await runtime.sidecar.tryCall("child.complete", {
        handle,
        result: { notice: true },
      });
      // §11.4/W7 child observation point: keep a vaulted credential available
      // for the child's Gate A submission path (best-effort, never blocking).
      const childId = String(handle.rlm_child_id ?? handle.child_id ?? "");
      await deliverChildCredential(runtime, childId);
    }
    return undefined;
  });

  on("session_before_compact", async (event) => {
    if (!runtime.sessionActive) {
      return undefined;
    }
    const summaryHash = sha256Hex(JSON.stringify(event.preparation ?? event));
    const recorded = await runtime.sidecar.tryCall("lifecycle.record", {
      event_type: "session_before_compact",
      payload: { summary_hash: summaryHash },
    });
    const checkpoint = await runtime.sidecar.tryCall("run.checkpoint");
    if (recorded === undefined || checkpoint === undefined) {
      runtime.telemetry.event("error", "ayran.compact.checkpoint_failed", {
        outcome: "cancelled",
      });
      return { cancel: true };
    }
    runtime.telemetry.event("info", "ayran.compact.before", {
      summary_hash: summaryHash,
    });
    return undefined;
  });

  on("session_compact", async (event) => {
    if (!runtime.sessionActive) {
      return undefined;
    }
    const summaryHash = sha256Hex(
      JSON.stringify(event.compactionEntry ?? event),
    );
    await runtime.sidecar.tryCall("lifecycle.record", {
      event_type: "session_compact",
      payload: { summary_hash: summaryHash },
    });
    if (!runtime.injectionActive) {
      runtime.telemetry.event("info", "ayran.compact.after", {
        summary_hash: summaryHash,
        reconstruction_ok: false,
        skipped: true,
      });
      return undefined;
    }
    const pack = (await runtime.sidecar.tryCall("context.pack", {
      token_budget: runtime.settings.contextPackTokenBudget,
      purpose: "audit-turn",
      role: "root-auditor",
    })) as PackResult | undefined;
    runtime.telemetry.event("info", "ayran.compact.after", {
      summary_hash: summaryHash,
      reconstruction_ok: Boolean(pack?.reconstruction_ok),
      content_hash: pack?.content_hash,
    });
    return undefined;
  });

  on("session_before_switch", async (event) => {
    if (!runtime.sessionActive) {
      return undefined;
    }
    await runtime.sidecar.tryCall("lifecycle.record", {
      event_type: "session_before_switch",
      payload: { reason: String(event.reason ?? "switch") },
    });
    const checkpoint = await runtime.sidecar.tryCall("run.checkpoint");
    if (checkpoint === undefined) {
      return { cancel: true };
    }
    return undefined;
  });

  on("session_before_fork", async () => {
    if (!runtime.sessionActive) {
      return undefined;
    }
    await runtime.sidecar.tryCall("lifecycle.record", {
      event_type: "session_before_fork",
      payload: { reason: "fork" },
    });
    const checkpoint = await runtime.sidecar.tryCall("run.checkpoint");
    if (checkpoint === undefined) {
      return { cancel: true };
    }
    return undefined;
  });

  on("session_shutdown", async (event, ctx: ExtensionContext) => {
    if (runtime.closed) {
      return;
    }
    runtime.closed = true;
    if (runtime.sessionActive) {
      const timeout = runtime.settings.shutdownTimeoutMs;
      const shutdown = runtime.sidecar
        .call("run.shutdown")
        .catch(() => undefined);
      const timer = new Promise((resolve) => {
        setTimeout(resolve, timeout);
      });
      await Promise.race([shutdown, timer]);
      if (runtime.spawnedSidecar) {
        stopSpawnedSidecar(runtime);
      }
    }
    runtime.sidecar.close();
    runtime.telemetry.event("info", "ayran.shutdown", {
      reason: String(event.reason ?? "quit"),
      outcome: "complete",
    });
    void ctx;
  });

  return registered;
}
