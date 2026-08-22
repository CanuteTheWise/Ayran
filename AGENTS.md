# AGENTS.md — implementation law for this repository

These rules govern all implementation work on Ayran. They override convenience,
schedule pressure, and agent discretion.

1. **Red-suite stop rule.** After every task, run the full test suite. Any red
   test halts progression until green. No milestone closes, and no commit
   message claims completion, unless the suite is green. Never mark a failing
   test skipped to proceed.
2. **Strict milestone sequencing.** Milestones execute strictly sequentially
   R0→R6 per the completion specification (canonical spec lives under
   `docs/audit-Ox/`, local-only).
3. **Zero new runtime dependencies, always.** Python stdlib only for anything
   added; no new packages, frameworks, or runtime deps.
