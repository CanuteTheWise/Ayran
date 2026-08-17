# Prime package boundary

M3 ships a stock Prime-Agent 0.7.2 package. Root `package.json` declares the
`pi` manifest: the TypeScript lifecycle extension, the `ayran` Python-backed
skill, specialist skill shells, and prompt templates.

The extension talks only to the M2 UDS JSON-RPC sidecar. It does not import
`prime-agent` at runtime and does not modify Prime source. `APPEND_SYSTEM.md`
is not a package resource; the launcher copies
`.prime-template/agent/APPEND_SYSTEM.md` into a trusted workspace at
`.prime/agent/APPEND_SYSTEM.md`.
