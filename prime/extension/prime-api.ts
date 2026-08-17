/**
 * Local structural types matching Prime-Agent 0.7.2 public extension surfaces.
 * The extension does not import prime-agent at runtime.
 */

export interface CustomMessage {
  customType: string;
  content: string;
  display: boolean;
  details?: unknown;
}

export interface ExtensionContext {
  ui: {
    notify(message: string, type?: "info" | "warning" | "error"): void;
  };
  hasUI: boolean;
  cwd: string;
  sessionManager: {
    getSessionFile?: () => string | undefined;
  };
  shutdown(): void;
  getSystemPrompt(): string;
}

export interface ExtensionCommandContext extends ExtensionContext {
  waitForIdle(): Promise<void>;
}

export type HookHandler = (
  event: Record<string, unknown>,
  ctx: ExtensionContext,
) => unknown | Promise<unknown>;

export interface RegisteredCommandOptions {
  description?: string;
  handler: (args: string, ctx: ExtensionCommandContext) => Promise<void>;
}

export interface ExtensionAPI {
  on(event: string, handler: HookHandler): void;
  registerCommand(name: string, options: RegisteredCommandOptions): void;
  sendMessage(
    message: CustomMessage,
    options?: {
      triggerTurn?: boolean;
      deliverAs?: "steer" | "followUp" | "nextTurn";
    },
  ): void;
  appendEntry(customType: string, data?: unknown): void;
}

export type ExtensionFactory = (pi: ExtensionAPI) => void | Promise<void>;
