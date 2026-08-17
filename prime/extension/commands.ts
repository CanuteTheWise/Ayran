import type { ExtensionAPI, ExtensionCommandContext } from "./prime-api.ts";
import type { RuntimeState } from "./bootstrap.ts";

function formatResult(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function notify(
  ctx: ExtensionCommandContext,
  message: string,
  type: "info" | "warning" | "error",
): void {
  if (ctx.hasUI) {
    ctx.ui.notify(message.slice(0, 4000), type);
  }
}

export function registerCommands(
  pi: ExtensionAPI,
  runtime: RuntimeState,
): void {
  pi.registerCommand("ayran:status", {
    description:
      "Show sidecar status: graph health, active runs, and tool availability.",
    handler: async (_args, ctx) => {
      const result = await runtime.sidecar.tryCall("run.status");
      if (result === undefined) {
        notify(ctx, "Ayran sidecar unreachable.", "warning");
        runtime.telemetry.event("warn", "ayran.command.status.unreachable", {
          outcome: "degraded",
        });
        return;
      }
      notify(ctx, formatResult(result), "info");
    },
  });

  pi.registerCommand("ayran:doctor", {
    description:
      "Run diagnostics: sidecar connectivity, journal integrity, policy load, tool detection.",
    handler: async (_args, ctx) => {
      const result = await runtime.sidecar.tryCall("run.doctor");
      if (result === undefined) {
        notify(ctx, "Ayran sidecar unreachable.", "warning");
        runtime.telemetry.event("warn", "ayran.command.doctor.unreachable", {
          outcome: "degraded",
        });
        return;
      }
      notify(ctx, formatResult(result), "info");
    },
  });

  pi.registerCommand("ayran:stop", {
    description:
      "Gracefully stop the current run and request sidecar shutdown.",
    handler: async (_args, ctx) => {
      const stopped = await runtime.sidecar.tryCall("run.stop", {
        graceful: true,
      });
      const shutdown = await runtime.sidecar.tryCall("run.shutdown");
      if (stopped === undefined && shutdown === undefined) {
        notify(ctx, "Ayran sidecar unreachable; nothing stopped.", "warning");
        return;
      }
      notify(ctx, formatResult({ stopped, shutdown }), "info");
    },
  });

  pi.registerCommand("ayran:recover", {
    description: "Recover a stale run: reclaim leases and verify the journal.",
    handler: async (_args, ctx) => {
      const result = await runtime.sidecar.tryCall("run.recover");
      if (result === undefined) {
        notify(ctx, "Ayran sidecar unreachable.", "warning");
        return;
      }
      notify(ctx, formatResult(result), "info");
    },
  });
}
