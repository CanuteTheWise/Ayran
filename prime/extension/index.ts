/**
 * Ayran Prime 0.7.2 lifecycle bridge.
 * Stock Prime loads this module from package.json `pi.extensions`. Prime source is not modified.
 */

import { createRuntime, type RuntimeState } from "./bootstrap.ts";
import { registerCommands } from "./commands.ts";
import { registerHooks } from "./hooks.ts";
import type { ExtensionAPI } from "./prime-api.ts";

export type { ExtensionAPI, ExtensionFactory } from "./prime-api.ts";
export { createRuntime, loadSettings } from "./bootstrap.ts";
export { registerCommands } from "./commands.ts";
export { registerHooks } from "./hooks.ts";
export { SidecarClient, SidecarError } from "./sidecar.ts";

export function activate(
  pi: ExtensionAPI,
  cwd = process.cwd(),
  runtime: RuntimeState = createRuntime(cwd),
): RuntimeState {
  try {
    if (typeof pi.registerFlag === "function") {
      pi.registerFlag("ayran", {
        description: "Start the Ayran sidecar for this session",
        type: "boolean",
        default: false,
      });
    }
    if (typeof pi.getFlag === "function" && pi.getFlag("ayran")) {
      runtime.sessionActive = true;
    }
    registerHooks(pi, runtime);
    registerCommands(pi, runtime);
    runtime.telemetry.event("info", "ayran.extension.loaded", {
      sidecar_configured: Boolean(runtime.settings.sidecarSocketPath),
      session_active: runtime.sessionActive,
    });
  } catch (error) {
    runtime.telemetry.event("error", "ayran.extension.load_failed", {
      outcome: "degraded",
      error_class: error instanceof Error ? error.name : "unknown",
    });
  }
  return runtime;
}

export default function ayranExtension(pi: ExtensionAPI): void {
  activate(pi);
}
