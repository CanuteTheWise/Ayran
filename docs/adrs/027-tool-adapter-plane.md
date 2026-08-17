---

status: accepted (2026-08-13)

---

# ADR 027 — Tool adapter plane

## Context

M4 must let Ayran detect, health-check, invoke, parse, and store evidence from
the operator's existing WSL audit tools (solc 0.8.28, Foundry 1.7.1, Slither
0.11.5) plus a Solodit HTTP search client. Adapters must never mutate those
tools. Installation is designed but disabled. The M0 capability-manifest and
tool-run contracts already exist; M1 journals and M2 sidecar/policy/process
are the only mutation path. Zero new runtime dependencies are allowed.
PyYAML is not a runtime dependency.

The build prompt's YAML sketch does not match
`schemas/capability-manifest.schema.json`. Manifests must use M0
`Identifier` values (`^[a-z][a-z0-9]{1,11}_[0-9A-HJKMNP-TV-Z]{26}$`),
Crockford alphabet (no I/L/O/U), `memory_mib`/`disk_mib`, a top-level
`timeout_seconds`, a closed `failure_taxonomy` enum, and RFC 8785
`integrity.content_hash` excluding that field.

## Decision

1. **Human aliases vs sealed IDs.** Operator-facing names live in
   `triggers[0]`: `solc.compile`, `foundry.test`, `slither.analyze`,
   `solodit.search`. Stable capability IDs are:
   - `cap_01J4S0C0000000000000000001` (solc)
   - `cap_01J4F0RG000000000000000001` (foundry)
   - `cap_01J4S1TH000000000000000001` (slither; no `L`)
   - `cap_01J4S0DT000000000000000001` (solodit)
   CLI, RPC, and registry lookup accept either the ID or the alias.

2. **Two adapter families, never a shell.** `ExecutableAdapter` wraps
   subprocess with `shell=False`, `start_new_session=True`, argv arrays
   built from templates (no raw shell strings), allowlisted environment
   (`PATH`, `HOME`, `TMPDIR`, plus adapter-declared names), SHA-256 of the
   executable and inputs/outputs, a 50 MiB spool cap with a `TRUNCATED`
   marker, and SIGTERM → grace → SIGKILL of the process group (`/proc`
   absence check on Linux). `HttpAdapter` wraps stdlib `urllib` with a
   response-size cap (10 MiB), conservative rate limiting, and a 3 s
   detect timeout. HTTP probes are **not** run at registry load.

3. **No evidence inference.** Exit code 0 does not validate output. Empty
   or malformed output with exit 0 is a parse failure. Parsers return
   normalized records; the manifest `evidence_ceiling` caps use:
   - solc / Foundry: `observed`
   - Slither / Solodit: `lead`
   A lead cannot be promoted to `observed` or `validated` in M4. That is
   an M6 evidence-pipeline concern. Parser guesses never become findings.

4. **Registry fail-closed.** Manifests load from `capabilities/*.yaml`,
   validate against `capability-manifest`, and probe detect argv (not HTTP)
   at load. Status is `available | unavailable_not_found |
   unavailable_wrong_version | unavailable_broken | unverified`.
   `get_adapter(id)` fails closed unless status is `available`. Health is
   lazy with a TTL cache. Optional tools degrade explicitly.

5. **Sidecar is the only mutator.** `ayran.tools.recording.record_tool_run`
   is the sole journal writer for ToolRun. The tools package never opens
   the journal or SQLite itself. Sidecar RPC `tools.list|detect|health|run`
   is authenticated with the existing per-run bearer and
   `policy.authorize` (`compile_local` / `test_local` /
   `approved_api_query`). One invocation produces one ToolRun; retries are
   new ToolRuns linked only through provenance lineage (the ToolRun schema
   has no `retries_from`).

6. **Target projects are read-only.** Foundry always `copytree`s into a
   run-scoped temp directory (`ayran-tool-copy-foundry-*`), ignoring
   `out/`, `cache/`, `broadcast/`, and `.git`. Fork URLs are stored as a
   hashed `fork_identity_hash` / `fork_url_ref`, never as the URL.
   Environment values are hashed, not logged.

7. **Solodit privacy.** Queries may not contain target-specific identifiers
   (0x-prefixed 40/64 hex, target-ish names, URLs). Abstract /
   mechanism-based queries only. Every result must carry `source_url` and
   `record_id`. Provider terms are captured at first use. Cache is keyed by
   a canonical query hash, stored in the artifact store, with a configurable
   TTL. Tests mock HTTP; live API calls are not part of the suite.

8. **Installer designed, never enabled.** `plan_install` returns an
   `InstallPlan` (tool, version, source, expected hash, prefix, resource
   forecast, DrvFS warning, rollback/cleanup). Config `enabled: false`.
   Even `allow_install=true` is refused with an explicit message. Receipts
   are machine-readable JSON listing created paths and prior pointers;
   rollback restores the prior pointer and removes only receipt-listed
   paths. Adapters never copy, install, upgrade, or modify Foundry /
   Slither / solc.

9. **YAML without a runtime YAML library.** Manifests are authored as a
   restricted YAML 1.2 subset (`yaml_lite`) so PyYAML is not added as a
   runtime dependency. Integrity hashes use the same RFC 8785
   `object_hash` path as M1.

10. **Detection strategy.** Executable detect runs the manifest `detect.argv`
    (`solc --version`, `forge --version`, `slither --version`) and parses
    with a version regex. Foundry additionally requires `cast` and `anvil`.
    Compatibility is the manifest upstream version. Solodit detect is an
    HTTP health check against a configurable endpoint, invoked on
    `health()` / doctor, not at registry construction. Unavailable optional
    tools remain listed with an explicit status; they do not fail the
    process.

## Consequences

* Windows can validate manifests, parsers, argv construction, privacy,
  truncation, timeout, environment filtering, ToolRun recording, and CLI
  list/detect/health/doctor without the WSL toolchain present.
* Real compile/test/analyze runs are `wsl_ext4` tests against the operator's
  existing tools. Those tests skip on Windows.
* M5 (context compiler / six-origin router) and M6 (evidence gates) remain
  unimplemented. Expansion adapters (Echidna, Medusa, Halmos) stay in the
  §22.1 backlog.
* Prime 0.7.2, the live Prime install, and the locked dependency set are
  untouched. M9 Complete URL-closure remains open.
