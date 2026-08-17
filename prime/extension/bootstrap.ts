/**
 * Layered extension settings. Prime's settings.json may carry an `ayran` object;
 * environment variables supply socket and token *paths* only, never token values.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import type { ChildProcess } from "node:child_process";
import { SidecarClient } from "./sidecar.ts";
import { Telemetry, type TelemetryLevel } from "./telemetry.ts";

export const DEFAULT_HOOKS = [
  "session_start",
  "resources_discover",
  "before_agent_start",
  "context",
  "tool_call",
  "tool_result",
  "message_end",
  "session_before_compact",
  "session_compact",
  "session_before_switch",
  "session_before_fork",
  "session_start_transition",
  "session_shutdown",
] as const;

export interface AyranSettings {
  sidecarSocketPath: string;
  runId: string;
  tokenFile: string;
  contextPackTokenBudget: number;
  enabledHooks: string[];
  telemetryVerbosity: TelemetryLevel;
  shutdownTimeoutMs: number;
  contextPackHeader: string;
}

export interface RuntimeState {
  settings: AyranSettings;
  sidecar: SidecarClient;
  telemetry: Telemetry;
  kernelManaged: boolean | undefined;
  lastPackHash: string | undefined;
  lastSessionReason: string | undefined;
  closed: boolean;
  sessionActive: boolean;
  sidecarProcess: ChildProcess | undefined;
  spawnedSidecar: boolean;
  autoStartSidecar: boolean;
}

interface SettingsFile {
  ayran?: Partial<AyranSettings> & {
    sidecarSocketPath?: string;
    tokenFile?: string;
  };
  rlmMaxDepth?: number;
}

function readJson(path: string): SettingsFile {
  const raw = readFileSync(path, "utf8");
  return JSON.parse(raw) as SettingsFile;
}

function findSettingsFile(cwd: string): string | undefined {
  const fromEnv = process.env.AYRAN_SETTINGS_PATH;
  if (fromEnv && existsSync(fromEnv)) {
    return fromEnv;
  }
  const candidates = [
    join(cwd, ".prime", "agent", "settings.json"),
    join(cwd, ".prime-template", "agent", "settings.json"),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

function readHeader(cwd: string): string {
  const path = join(cwd, "prime", "prompts", "context-pack-header.md");
  if (existsSync(path)) {
    return readFileSync(path, "utf8");
  }
  const fallback = join(
    dirname(cwd),
    "prime",
    "prompts",
    "context-pack-header.md",
  );
  if (existsSync(fallback)) {
    return readFileSync(fallback, "utf8");
  }
  return "# Ayran context pack\n\nBounded Target Graph state follows. It is not a complete corpus.\n";
}

export function loadSettings(cwd: string): AyranSettings {
  const settingsPath = findSettingsFile(cwd);
  const file = settingsPath ? readJson(settingsPath) : {};
  const nested = file.ayran ?? {};
  const budgetRaw =
    process.env.AYRAN_CONTEXT_PACK_TOKEN_BUDGET ??
    nested.contextPackTokenBudget;
  const budget =
    typeof budgetRaw === "number"
      ? budgetRaw
      : Number.parseInt(String(budgetRaw || "4000"), 10);
  return {
    sidecarSocketPath:
      process.env.AYRAN_SOCKET_PATH || nested.sidecarSocketPath || "",
    runId: process.env.AYRAN_RUN_ID || nested.runId || "",
    tokenFile: process.env.AYRAN_TOKEN_FILE || nested.tokenFile || "",
    contextPackTokenBudget: Number.isFinite(budget) ? budget : 4000,
    enabledHooks: nested.enabledHooks ?? [...DEFAULT_HOOKS],
    telemetryVerbosity: nested.telemetryVerbosity ?? "info",
    shutdownTimeoutMs: nested.shutdownTimeoutMs ?? 5000,
    contextPackHeader: readHeader(cwd),
  };
}

export function createRuntime(cwd: string): RuntimeState {
  const settings = loadSettings(cwd);
  const logPath = settings.sidecarSocketPath
    ? join(
        dirname(resolve(settings.sidecarSocketPath)),
        "extension-telemetry.jsonl",
      )
    : undefined;
  const telemetry = new Telemetry(settings.telemetryVerbosity, logPath);
  const sidecar = new SidecarClient(
    settings.sidecarSocketPath,
    settings.tokenFile,
  );
  return {
    settings,
    sidecar,
    telemetry,
    kernelManaged: undefined,
    lastPackHash: undefined,
    lastSessionReason: undefined,
    closed: false,
    sessionActive: Boolean(settings.sidecarSocketPath),
    sidecarProcess: undefined,
    spawnedSidecar: false,
    autoStartSidecar: true,
  };
}

export function bindSidecar(
  runtime: RuntimeState,
  socketPath: string,
  tokenFile: string,
  runId: string,
): void {
  runtime.settings.sidecarSocketPath = socketPath;
  runtime.settings.tokenFile = tokenFile;
  runtime.settings.runId = runId;
  runtime.sidecar = new SidecarClient(socketPath, tokenFile);
}

export async function detectKernel(runtime: RuntimeState): Promise<void> {
  const result = (await runtime.sidecar.tryCall("kernel.detect")) as
    { managed?: boolean; warning?: string } | undefined;
  if (!result) {
    runtime.telemetry.event("warn", "ayran.kernel.sidecar_unreachable", {
      outcome: "degraded",
    });
    return;
  }
  runtime.kernelManaged = Boolean(result.managed);
  if (!result.managed) {
    runtime.telemetry.event("warn", "ayran.kernel.custom", {
      outcome: "warning",
      reason_code: "custom_python_kernel",
    });
  }
}
