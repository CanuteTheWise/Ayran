/**
 * Spawn ``ayran service`` for ``prime-agent --ayran``.
 * Paths only; token bytes stay in the token file.
 */

import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { bindSidecar, type RuntimeState } from "./bootstrap.ts";

const PING_ATTEMPTS = 40;
const PING_DELAY_MS = 150;

export function resolveAyranPython(): string {
  const fromEnv = process.env.AYRAN_PYTHON;
  if (fromEnv && existsSync(fromEnv)) {
    return fromEnv;
  }
  const venv =
    process.env.AYRAN_VENV || join(homedir(), ".local", "ayran-venv");
  const unix = join(venv, "bin", "python");
  if (existsSync(unix)) {
    return unix;
  }
  const windows = join(venv, "Scripts", "python.exe");
  if (existsSync(windows)) {
    return windows;
  }
  return "python3";
}

export function resolveScopeManifest(cwd: string, explicit?: string): string {
  const candidates: string[] = [];
  if (explicit?.trim()) {
    const value = explicit.trim();
    candidates.push(value);
    candidates.push(resolve(cwd, value));
  }
  const fromEnv = process.env.AYRAN_SCOPE;
  if (fromEnv?.trim()) {
    candidates.push(fromEnv.trim());
    candidates.push(resolve(cwd, fromEnv.trim()));
  }
  candidates.push(join(cwd, ".ayran", "scope.json"));
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return "";
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function parsePrepare(stdout: string): {
  run_id: string;
  state_root: string;
  socket: string;
  token_file: string;
  reattached?: boolean;
} {
  const parsed = JSON.parse(stdout) as {
    ok?: boolean;
    result?: {
      run_id?: string;
      state_root?: string;
      socket?: string;
      token_file?: string;
      reattached?: boolean;
    };
  };
  const result = parsed.result;
  if (
    parsed.ok !== true ||
    !result?.run_id ||
    !result.state_root ||
    !result.socket ||
    !result.token_file
  ) {
    throw new Error("ayran session prepare did not return run paths");
  }
  return {
    run_id: result.run_id,
    state_root: result.state_root,
    socket: result.socket,
    token_file: result.token_file,
    reattached: result.reattached === true,
  };
}

export async function ensureSidecar(
  runtime: RuntimeState,
  cwd: string,
): Promise<boolean> {
  if (!runtime.autoStartSidecar) {
    return true;
  }
  if (runtime.sidecar.reachable || runtime.sidecarProcess) {
    return true;
  }
  runtime.lastSidecarCwd = cwd;
  if (runtime.settings.sidecarSocketPath) {
    const ping = await runtime.sidecar.tryCall("run.ping");
    if (ping !== undefined) {
      return true;
    }
  }
  const python = resolveAyranPython();
  const manifest = runtime.scopeManifestPath;
  const prepareArgs = ["-m", "ayran.cli", "start", "--cwd", cwd];
  if (manifest.length > 0) {
    prepareArgs.push("--manifest", manifest);
  }
  if (process.env.AYRAN_FRESH === "1") {
    prepareArgs.push("--fresh");
  }
  const prepared = spawnSync(python, prepareArgs, {
    encoding: "utf8",
    timeout: 30_000,
  });
  if (prepared.status !== 0) {
    runtime.telemetry.event("error", "ayran.session.prepare_failed", {
      outcome: "degraded",
      error_class: "prepare",
    });
    return false;
  }
  let paths: ReturnType<typeof parsePrepare>;
  try {
    paths = parsePrepare(prepared.stdout);
  } catch {
    runtime.telemetry.event("error", "ayran.session.prepare_failed", {
      outcome: "degraded",
      error_class: "parse",
    });
    return false;
  }
  bindSidecar(runtime, paths.socket, paths.token_file, paths.run_id);
  if (paths.reattached) {
    // Python reported a healthy guard already owning this run's socket with
    // the CURRENT token: no rotation happened and no second service may
    // spawn (it would be refused). Confirm liveness once, then done.
    const ping = await runtime.sidecar.tryCall("run.ping");
    if (ping !== undefined) {
      runtime.telemetry.event("info", "ayran.session.sidecar_reattached", {
        run_id: paths.run_id,
      });
      return true;
    }
    runtime.telemetry.event("warn", "ayran.session.reattach_lapsed", {
      run_id: paths.run_id,
      outcome: "degraded",
    });
    // Fall through: the guard died between prepare and now; the token file
    // is still authoritative, so a fresh spawn reuses it unchanged.
  }
  const child: ChildProcess = spawn(
    python,
    [
      "-m",
      "ayran.cli",
      "service",
      "--run",
      paths.run_id,
      "--state-root",
      paths.state_root,
      "--socket",
      paths.socket,
      "--token-file",
      paths.token_file,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  runtime.sidecarProcess = child;
  runtime.spawnedSidecar = true;
  for (let attempt = 0; attempt < PING_ATTEMPTS; attempt += 1) {
    const ping = await runtime.sidecar.tryCall("run.ping");
    if (ping !== undefined) {
      runtime.telemetry.event("info", "ayran.session.sidecar_ready", {
        run_id: paths.run_id,
      });
      return true;
    }
    if (child.exitCode !== null) {
      break;
    }
    await sleep(PING_DELAY_MS);
  }
  runtime.telemetry.event("error", "ayran.session.sidecar_timeout", {
    outcome: "degraded",
  });
  return false;
}

export function stopSpawnedSidecar(runtime: RuntimeState): void {
  const child = runtime.sidecarProcess;
  if (!child?.pid || child.exitCode !== null) {
    return;
  }
  try {
    child.kill("SIGTERM");
  } catch {
    return;
  }
}
