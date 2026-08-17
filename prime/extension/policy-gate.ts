/**
 * Best-effort ipython payload blocking. This is not a sandbox.
 * Real filesystem, network, and process enforcement remains outside Prime.
 */

const DISALLOWED = [
  /\bsubprocess\.run\b/,
  /\bsubprocess\.Popen\b/,
  /\bos\.system\b/,
  /\bos\.popen\b/,
  /\bimport\s+ctypes\b/,
  /\bfrom\s+ctypes\b/,
  /\bctypes\./,
];

export const NOT_A_SANDBOX_WARNING =
  "Best-effort block only. This is not a sandbox; real enforcement is the external OS, WSL, or container boundary.";

export function disallowedIpython(code: string): boolean {
  return DISALLOWED.some((pattern) => pattern.test(code));
}

export function ipythonBlockReason(code: string): string | undefined {
  if (!disallowedIpython(code)) {
    return undefined;
  }
  return `ipython payload matches a disallowed pattern. ${NOT_A_SANDBOX_WARNING}`;
}
