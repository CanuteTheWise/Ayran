/**
 * Extension-side credential minting (spec §11.4, R5 W7 relocation).
 *
 * Key GENERATION lives only here — outside model-reachable Python. The sidecar
 * receives the key once via the `credentials.enroll` RPC (bearer-authenticated
 * channel; the key never appears in env values, argv, or logs) and afterwards
 * only verifies and consumes tokens against it. Per-spawn challenger tokens
 * are minted here and vaulted server-side via `credentials.deliver`; the model
 * never handles a challenger token.
 *
 * Wire format — byte-compatible with `ayran.gates.credentials` (Python):
 *   body       = base64url(JSON.stringify(payload with SORTED keys), unpadded)
 *   signature  = HMAC-SHA256 lowercase hex over body (ascii)
 *   token      = body + "." + signature
 * Payload fields are exactly jti (16 hex), iat, exp, grants (sorted), writer,
 * child_id, session. Honest HMAC caveat: the key is symmetric, so
 * post-enrollment the sidecar COULD mint; mint-separation for challenger
 * tokens is procedural, while single-use / TTL / child-binding enforcement
 * stays cryptographic and server-side.
 */

import { createHmac, randomBytes } from "node:crypto";
import type { RuntimeState } from "./bootstrap.ts";

export const CREDENTIAL_GRANT_REMEMBER = "hypotheses.remember";
export const CREDENTIAL_GRANT_GATE_A = "gate_a_submission";
export const DEFAULT_TTL_SECONDS = 300;
export const SESSION_KEY_BYTES = 32;

export type CredentialGrant =
  | typeof CREDENTIAL_GRANT_REMEMBER
  | typeof CREDENTIAL_GRANT_GATE_A;

export interface CredentialPayload {
  jti: string;
  iat: number;
  exp: number;
  grants: string[];
  writer: Record<string, string> | null;
  child_id: string | null;
  session: string | null;
}

export interface MintOptions {
  grants: CredentialGrant[];
  writer?: Record<string, string>;
  child_id?: string;
  session?: string;
  ttlSeconds?: number;
  nowSeconds?: number;
  jti?: string;
}

/** Deep key-sorted JSON.stringify (Python json.dumps(sort_keys=True) parity). */
function sortedStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) as string;
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => sortedStringify(item)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${sortedStringify(record[key])}`)
    .join(",")}}`;
}

export function encodeCredentialBody(
  payload: CredentialPayload,
): string {
  return Buffer.from(sortedStringify(payload), "utf8").toString("base64url");
}

export function signCredentialBody(
  body: string,
  key: Buffer,
): string {
  return createHmac("sha256", key).update(body, "ascii").digest("hex");
}

export class CredentialMinter {
  /** 32-byte random session key; generated here, enrolled once, never logged. */
  readonly key: Buffer;

  constructor(key: Buffer = randomBytes(SESSION_KEY_BYTES)) {
    if (key.length !== SESSION_KEY_BYTES) {
      throw new Error(`credential session key must be ${SESSION_KEY_BYTES} bytes`);
    }
    this.key = key;
  }

  keyB64(): string {
    return this.key.toString("base64");
  }

  mint(options: MintOptions): string {
    const iat = options.nowSeconds ?? Math.floor(Date.now() / 1000);
    const ttl = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
    const payload: CredentialPayload = {
      jti: options.jti ?? randomBytes(8).toString("hex"),
      iat,
      exp: iat + ttl,
      grants: [...options.grants].sort(),
      writer: options.writer ?? null,
      child_id: options.child_id ?? null,
      session: options.session ?? null,
    };
    const body = encodeCredentialBody(payload);
    return `${body}.${signCredentialBody(body, this.key)}`;
  }

  mintChallenger(childId: string, ttlSeconds = DEFAULT_TTL_SECONDS): string {
    return this.mint({
      grants: [CREDENTIAL_GRANT_GATE_A],
      child_id: childId,
      ttlSeconds,
    });
  }
}

export interface EnrollOutcome {
  attempted: boolean;
  accepted: boolean;
  code?: string;
}

/**
 * Enroll the runtime's session key with the sidecar. Idempotent per runtime:
 * once an enrollment is accepted it is never retried (the sidecar refuses a
 * second enrollment with CREDENTIAL_ALREADY_ENROLLED, fail-closed).
 */
export async function enrollCredentials(
  runtime: RuntimeState,
): Promise<EnrollOutcome> {
  if (!runtime.sidecar || runtime.credentialsEnrolled) {
    return { attempted: false, accepted: runtime.credentialsEnrolled };
  }
  const result = (await runtime.sidecar.tryCall("credentials.enroll", {
    key_b64: runtime.credentials.keyB64(),
  })) as { accepted?: boolean; error?: { code?: string } } | undefined;
  const accepted = Boolean(result?.accepted);
  const code = result?.error?.code;
  if (accepted) {
    runtime.credentialsEnrolled = true;
    runtime.telemetry.event("info", "ayran.credentials.enrolled", {
      outcome: "accepted",
    });
  } else {
    runtime.telemetry.event("warn", "ayran.credentials.enroll_refused", {
      outcome: "degraded",
      error_code: code ?? "sidecar_unreachable",
    });
  }
  return { attempted: true, accepted, code };
}

/**
 * Mint a child-bound gate_a_submission token and vault it server-side
 * (§11.4/W7). Failures are tolerated silently: child tracking and degraded
 * operation must never depend on credential delivery, and tokens/key material
 * are never logged.
 */
export async function deliverChildCredential(
  runtime: RuntimeState,
  childId: string,
): Promise<void> {
  if (!runtime.sidecar || !childId) {
    return;
  }
  try {
    const token = runtime.credentials.mintChallenger(childId);
    await runtime.sidecar.tryCall("credentials.deliver", {
      child_id: childId,
      // "credential", never "token": params.token is the run bearer on the wire.
      credential: token,
    });
  } catch {
    // Best-effort: an undeliverable vault entry only means Gate A must use an
    // explicit credential channel later.
  }
}
