/**
 * Owner-local JSON-RPC 2.0 client over a Unix-domain socket.
 * Token values are sent in params.token and are never logged.
 */

import { createConnection } from "node:net";
import { readFileSync } from "node:fs";

export class SidecarError extends Error {
  constructor(
    message: string,
    readonly code?: unknown,
  ) {
    super(message);
    this.name = "SidecarError";
  }
}

export type SidecarFailureKind = "unreachable" | "auth" | "error";

function classifyFailure(error: unknown): SidecarFailureKind {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes("token mismatch")) {
    // The guard is alive but holds a different bearer generation than disk.
    return "auth";
  }
  if (
    message.includes("ENOENT") ||
    message.includes("ECONNREFUSED") ||
    message.includes("connect") ||
    message.includes("timed out") ||
    message.includes("closed")
  ) {
    return "unreachable";
  }
  return "error";
}

export class SidecarClient {
  private token: string | undefined;
  private nextId = 1;
  reachable = false;
  /** Why the last tryCall failed, classified for honest denial messages. */
  lastFailure: SidecarFailureKind | undefined;

  constructor(
    private readonly socketPath: string,
    private readonly tokenFile: string,
    private readonly timeoutMs = 4000,
  ) {}

  loadToken(): void {
    if (!this.tokenFile) {
      return;
    }
    this.token = readFileSync(this.tokenFile, "utf8").trim();
  }

  async call(
    method: string,
    params: Record<string, unknown> = {},
  ): Promise<unknown> {
    try {
      return await this.attempt(method, params);
    } catch (error) {
      // Defect D4 fix: a rotated bearer used to strand the session until a
      // full restart. Reload the token file from disk and retry ONCE; the
      // wire format is untouched.
      if (!(error instanceof SidecarError) || classifyFailure(error) !== "auth") {
        throw error;
      }
      this.token = undefined;
      this.loadToken();
      return await this.attempt(method, params);
    }
  }

  private async attempt(
    method: string,
    params: Record<string, unknown>,
  ): Promise<unknown> {
    if (!this.socketPath) {
      throw new SidecarError("sidecar socket path is not configured");
    }
    if (this.token === undefined) {
      this.loadToken();
    }
    const id = this.nextId++;
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      method,
      params: { ...params, token: this.token ?? "" },
      id,
    });
    const raw = await this.roundTrip(`${payload}\n`);
    const frame = JSON.parse(raw) as {
      result?: unknown;
      error?: {
        message?: string;
        code?: unknown;
        details?: { code?: unknown };
      };
    };
    if (frame.error) {
      throw new SidecarError(
        frame.error.message ?? "sidecar error",
        frame.error.details?.code ?? frame.error.code,
      );
    }
    this.reachable = true;
    this.lastFailure = undefined;
    return frame.result;
  }

  async tryCall(
    method: string,
    params: Record<string, unknown> = {},
  ): Promise<unknown | undefined> {
    try {
      return await this.call(method, params);
    } catch (error) {
      this.reachable = false;
      this.lastFailure = classifyFailure(error);
      return undefined;
    }
  }

  close(): void {
    this.token = undefined;
    this.reachable = false;
  }

  private roundTrip(frame: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const connection = createConnection({ path: this.socketPath });
      const timer = setTimeout(() => {
        connection.destroy();
        reject(new SidecarError("sidecar request timed out"));
      }, this.timeoutMs);
      let buffer = "";
      connection.setEncoding("utf8");
      connection.on("connect", () => {
        connection.write(frame);
      });
      connection.on("data", (chunk: string) => {
        buffer += chunk;
        const newline = buffer.indexOf("\n");
        if (newline >= 0) {
          clearTimeout(timer);
          connection.end();
          resolve(buffer.slice(0, newline));
        }
      });
      connection.on("error", (error: Error) => {
        clearTimeout(timer);
        reject(new SidecarError(error.message));
      });
      connection.on("end", () => {
        if (!buffer.includes("\n")) {
          clearTimeout(timer);
          reject(new SidecarError("sidecar closed without a complete frame"));
        }
      });
    });
  }
}
