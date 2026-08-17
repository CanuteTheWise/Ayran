---

status: accepted (2026-08-13)

---

# ADR 026 — Prime 0.7.2 lifecycle bridge

## Context

M3 must load Ayran as a stock Prime-Agent 0.7.2 package (not a fork). Prime
0.7.2 exposes extensions, skills, prompts, and themes through `package.json`
`pi`, and fires a documented hook set. It does **not** emit
`child_spawn` / `child_complete` / `child_fail` / `session_switch` /
`session_fork` / a dedicated `shutdown` event. Authoritative graph state
already lives behind the M2 owner-only UDS JSON-RPC sidecar. The extension
must not add runtime npm dependencies, must not write journals or SQLite
itself, and must never present Python-cell filtering as OS sandboxing.

## Decision

1. **Pure package.** Root `package.json` declares `keywords: ["pi-package"]`
   and `pi.extensions` / `pi.skills` / `pi.prompts` with paths relative to
   the package root. Skills are `./skills/ayran` and `./skills/specialists`
   (not `./skills`, which would load `skills/README.md` as a skill). Prime
   source, including the vendored 0.7.2 archive, is never patched.
2. **Local structural types.** The extension copies the 0.7.2
   `ExtensionAPI` shape into `prime/extension/prime-api.ts` and does not
   import `prime-agent` at runtime, so `tsc --noEmit` stays closed without
   installing Prime's URL-locked transitive graph (the M9 Complete blocker).
3. **Hook mapping.** Blueprint names map onto 0.7.2 events:
   - `before_agent_start` → inject a persistent custom message
     `customType: ayran.context_pack`
   - `tool_call` → `{ block: true, reason }` or pass-through; `event.input`
     may be mutated in place
   - compact → `session_before_compact` then `session_compact`
   - switch → `session_before_switch` → `session_shutdown` → `session_start`
     `{ reason: "new"|"resume" }`
   - fork → `session_before_fork` → `session_shutdown` → `session_start`
     `{ reason: "fork" }`
   - shutdown → `session_shutdown` (`quit`/`reload`/`new`/`resume`/`fork`)
   - RLM children → observe `ipython` `tool_result` handles
     (`rlm_child_id`) and custom types `rlm_child_failure` /
     `rlm_child_terminal_notice`. The extension never calls `rlm()`.
     Workspace template sets `rlmMaxDepth: 1`.
4. **Sidecar is the only mutator.** Context packs, policy decisions,
   compaction/session/child records, checkpoints, and shutdown all go
   through UDS JSON-RPC (`context.pack`, `policy.authorize`,
   `lifecycle.record`, `child.*`, `run.checkpoint`, `run.shutdown`). Token
   bytes travel in `params.token` and are never logged.
5. **Degradation.** If the sidecar is unreachable: log a warning (hashes and
   status only), inject an empty-context note, fail closed on policy
   evaluation, and never throw out of a hook into Prime. Shutdown waits at
   most 5 seconds, then abandons the RPC so Prime can exit; the extension
   does not `process.exit()`.
6. **Policy gating is not a sandbox.** Mapped tools (`read`/`edit`/`write`,
   Ayran capabilities) are authorized against the M2 deny-wins scope.
   Unmapped Prime tools pass through unless `allowed_tools` is non-empty.
   Clearly disallowed `ipython` payloads (`subprocess.run`, `os.system`,
   `ctypes`, …) are best-effort blocked with an explicit not-a-sandbox
   warning. Real enforcement remains the external OS/WSL/container
   boundary.
7. **Workspace template vs package resources.** `APPEND_SYSTEM.md` is
   discovered only at `.prime/agent/APPEND_SYSTEM.md`. The package ships
   `.prime-template/agent/` for the launcher to copy into a trusted
   workspace. It is never installed into the untrusted target tree.
8. **Managed kernel.** The sidecar reports whether Prime's Python is the
   Complete-managed interpreter. Custom kernels get a warning; Ayran never
   installs or mutates the user's environment.

## Consequences

* Stock Prime 0.7.2 can load the package from a local path without source
  edits. UI and built-in tools remain intact.
* Compaction reconstruction (active hypothesis, result so far, next action,
  dead approaches, untried dimensions) is a sidecar/graph property, not a
  Prime transcript dump.
* Compatibility tests use a mock `ExtensionAPI` plus the same
  `JSON.parse(package.json).pi` discovery Prime uses. Full
  `createAgentSession` SDK runs remain blocked on M9 URL-closure.
* M4+ adapters and M5 driver bodies are out of scope; specialist skills are
  spawn shells only.

## Amendment (2026-08-17)

Context-pack injection on `before_agent_start` is gated by `/ayran:activate`
for the rest of the session. `prime-agent --ayran` still starts the sidecar
(and may bind a scope via `--ayran-manifest` / `ayran start --manifest`).
Until activate, greetings must not receive an `audit-turn` pack. If the
sidecar is unreachable *and* injection is on, the empty-context note and
fail-closed policy behavior in decision 5 still apply.
