---

status: accepted (2026-08-15)

---

# ADR 032 — Release evaluation, Complete URL-closure, signing, and distribution

## Context

M9 is the private-release gate. M0–M8 delivered contracts, journal, sidecar, Prime bridge, adapters, compiler/router, evidence, Global corpus, and Learning promotion. Evaluation was an A0/A1 ablation proxy. Complete release was blocked on Prime's URL-based transitive dependency closure. Manifest signatures were RFC 8785 content hashes "until M9 signing". Zero new runtime dependencies remain in force. Prime 0.7.2 commit `83a0f9f9566219551fcb6ffaf7f519a815749a58` stays unmodified.

## Decision

1. **Sealed evaluation controller owns A0–A7.**
   Blinded, stratified partitions by project family and root-cause family keep near-duplicates in one contamination group. Fixtures are opaque `sev_` IDs, hashed, and physically absent from Global/Learning ingestion. A leakage scan runs before every session. Offline fixture execution is honest: `execution_mode=sealed_fixture_offline` and `model_invoked=false`. Live model studies are separate. Results are immutable; errors create a new session.

2. **Complete URL-closure replaces URL indirection with content pins.**
   Ayran `package-lock.json` packages are pinned by npm integrity (plus a SHA-256 of that integrity). Prime `package.json` HTTPS tarball dependencies are pinned to SHA-256 of cached bytes when present, otherwise to a canonical pin over `{url, prime version, commit, parent archive SHA-256}` with `install_fetches=false`. Complete install does not run Prime postinstall URL fetches. `dist/manifests/complete-deps.json` is the reproducible closure. Identical inputs produce identical hashes. This unblocks `createAgentSession` SDK full tests at the dependency boundary.

3. **Signing is RFC 8785 → SHA-256.**
   Bundle metadata is canonicalized with RFC 8785 and hashed with SHA-256. The hash is written to a sidecar signature file. GPG code signing remains deferred. SBOM and THIRD-PARTY-NOTICES ship with both Layer and Complete.

4. **Layer and Complete ownership.**
   Layer attaches to an externally owned compatible Prime and never writes or removes it. Complete vendors unmodified Prime 0.7.2 under an Ayran-owned versioned prefix. Receipts list only created paths. Rollback restores the prior pointer. Uninstall removes receipt-listed paths only. External tools stay detect-only.

5. **Operations docs are operator artifacts.**
   Install, sessions/Target Graph pin, upgrade, security, troubleshooting, and evaluation documents live under `docs/operations/` and describe doctor output, receipts, and the A0–A7 gate without introducing a second UI.

## Consequences

- CLI `ayran eval *` and `ayran release *` are the operator surface.
- Sidecar methods `eval.*` and `release.*` are bearer-authenticated.
- Staging accepts the frozen M9 payload contract.
- A6/A7 Fizz remaining experimental and unbundled is reported as a failure in the evaluation manifest, not hidden.
- §22.1 deferred backlog stays deferred.

## Verification

Windows 2026-08-15: pytest 337 passed / 53 skipped, strict mypy 0 errors, ruff clean, tsc --noEmit, generate_contracts --check 4 artifacts, 142 Ajv fixtures, 152 TypeScript tests, Prettier 3.9.6. WSL ext4: 53 `wsl_ext4` tests passed including crash recovery and M9 sockets. Layer Plan twice identical then Stage. Sealed leakage scan clean. Layer/Complete rebuilds bit-identical. Receipt rollback/uninstall never remove external Prime or tools. Staging digest and bundle hashes live in `docs/development/evidence/m9-verification-summary.json`.
