---

status: accepted (2026-08-13)

---

# ADR 025 — Local API, configuration policy, and process authority

## Context

M2 adds the owner-only local API, layered configuration, scope/policy binding,
artifact storage, and supervised external-process control.  The blueprint
explicitly rules out remote transfer, model-faced credentials, model-executed
arbitrary code, and Windows/DrvFS storage for authoritative state.

## Decision

1. **Owner-local JSON-RPC sidecar only.**  The M2 service is bound to a
   per-run Unix-domain socket whose parent directory is restricted to the
   owner.  Connection admission checks ``SO_PEERCRED`` uid and then a
   run-scoped bearer in ``params.token``.  A wrong token or an unexpected
   uid maps to stable ``PERMISSION_DENIED``/``AUTHENTICATION_REQUIRED``
   codes; neither value is ever logged.
2. **Configuration precedence with recorded provenance.**  Built-in
   defaults, a private global file, a trusted project file, an engagement
   file, allowlisted environment variables, and explicit CLI overrides are
   folded in that exact order.  Each layer applied records its origin and
   value set.  Weakening a monotonic key (``journal_fsync``,
   ``security_override_allowed``, ``allow_install``, resource floors,
   sandbox-integrity flags) is rejected unless ``security_override_allowed =
   true`` was written in the *private global layer* only.
3. **Scope manifests pin interpretation to canonical content.**  The scope
   value hash is computed on the RFC 8785 canonical content after applying
   declared ``excluded_fields`` (mirroring §18 integrity semantics).  Deny
   rules always override allows; unknown action classes are FORBIDDEN, and
   absent scope => fail closed.
4. **Artifacts are content-addressed and immutable.**  A store write never
   rewrites existing bytes; it verifies the hash again and returns the
   deduplicated record.  New writes take a temp -> fsync -> rename ->
   directory-fsync path.  A deterministic secret scan blocks persistence of
   PEM-shaped secrets and ``x-api-key:`` / ``Authorization: Bearer`` markers.
5. **Processes are process-group-scoped and start-identity-bound.**  Every
   supervised process is created with ``start_new_session=True`` so it owns
   a new process group; SIGTERM targets the group; after a grace delay the
   group is SIGKILLed; afterwards a non-blocking ``killpg(pgid, 0)`` probe
   must report ``ESRCH`` before the supervisor considers the run complete.
   Records key on a fresh ``process_uid`` but carry
   ``(pid, process_start_identity, pgid)`` so a pid-reused zombie is
   unambiguously finalized as ``zombie_reaped`` during recovery.
6. **Launch failure is a no-child outcome.**  Argument validation and the
   binary-realpath's allowed-root check run *before* spawn; a rejected
   ``argv[0]`` or executable outside the allowed roots never forks.
7. **Logs and receipts are fsync'd per record.**  Runtime logs and the
   run-receipt atomically persist via the existing ``atomic_write`` helper;
   logger redaction drops any non-allowlisted key value before it is
   written.
8. **No runtime dependency was added for M2.**  The M2 runtime uses only
   stdlib Python plus the already-pinned ``jsonschema`` / ``pydantic`` /
   ``rfc8785`` baseline.  Prime remains untouched; the user's live
   Prime-Agent v0.7.1 installation is not modified.

## Consequences

* Host-local clients (Prime extension, specialist skills) communicate with
  the supervisor/data service over one typed, authentication-bound port.
* Configuration diffs and failures become auditable: ``doctor`` reads the
  recorded provenance instead of re-deriving it.
* Process termination is deterministic and testable; the owner-only socket
  and fsync'd process records give ``recover`` and ``status`` a durable
  ground truth even after SIGKILL.
* No Prime, kernel, or external tool installation is altered.  ``doctor``
  and ``compatibility.locks`` report facts against the existing M0/M1
  `prime-lock` and `platform-lock`.

