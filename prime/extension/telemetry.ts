/**
 * Hash-only telemetry. Token values and pack bodies are never logged.
 */

import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export type TelemetryLevel = "debug" | "info" | "warn" | "error";

const RANK: Record<TelemetryLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export class Telemetry {
  constructor(
    private readonly verbosity: TelemetryLevel,
    private readonly logPath?: string,
  ) {}

  event(
    level: TelemetryLevel,
    eventType: string,
    fields: Record<string, unknown> = {},
  ): void {
    if (RANK[level] < RANK[this.verbosity]) {
      return;
    }
    const record = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      event_type: eventType,
      ...fields,
    };
    const line = JSON.stringify(record);
    if (this.logPath) {
      try {
        mkdirSync(dirname(this.logPath), { recursive: true });
        appendFileSync(this.logPath, `${line}\n`, { encoding: "utf8" });
      } catch {
        process.stderr.write(`${line}\n`);
      }
    } else {
      process.stderr.write(`${line}\n`);
    }
  }
}
