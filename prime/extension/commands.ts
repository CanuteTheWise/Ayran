import type { ExtensionAPI, ExtensionCommandContext } from "./prime-api.ts";
import type { RuntimeState } from "./bootstrap.ts";
import { ensureSidecar, resolveScopeManifest } from "./launch.ts";

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
  pi.registerCommand("ayran:activate", {
    description:
      "Turn Ayran context-pack injection on for the rest of this session. Optional: /ayran:activate <scope-manifest.json>",
    handler: async (args, ctx) => {
      runtime.sessionActive = true;
      const requested = args.trim();
      runtime.scopeManifestPath = resolveScopeManifest(
        ctx.cwd,
        requested || runtime.scopeManifestPath,
      );
      const started = await ensureSidecar(runtime, ctx.cwd);
      if (!started && !runtime.sidecar.reachable) {
        notify(ctx, "Ayran sidecar could not be started.", "error");
        runtime.telemetry.event("error", "ayran.command.activate.sidecar", {
          outcome: "degraded",
        });
        return;
      }
      if (runtime.scopeManifestPath) {
        const loaded = await runtime.sidecar.tryCall("scope.load", {
          manifest: runtime.scopeManifestPath,
        });
        if (loaded === undefined) {
          notify(
            ctx,
            `Sidecar is up but the scope manifest could not be loaded: ${runtime.scopeManifestPath}`,
            "warning",
          );
        }
      }
      runtime.injectionActive = true;
      runtime.telemetry.event("info", "ayran.injection.enabled", {
        scope_bound: Boolean(runtime.scopeManifestPath),
      });
      notify(
        ctx,
        runtime.scopeManifestPath
          ? `Ayran injection is on for this session. Scope: ${runtime.scopeManifestPath}`
          : "Ayran injection is on for this session. Mapped audit tools stay fail-closed until a scope manifest is loaded.",
        "info",
      );
    },
  });

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
