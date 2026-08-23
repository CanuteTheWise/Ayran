# DeFiHackLabs parser fixtures

Status: **format-faithful reconstructions, clearly labeled synthetic** (R4
kickoff C4 forbids network access, so byte-verbatim upstream capture was
impossible during this pass). The header-card shape follows the documented
DeFiHackLabs facts: `src/test/<YYYY-MM>/<Protocol>_exp.sol` files whose
header comments carry the exploit tx hash, block anchor, attacker EOA,
harness/victim addresses, loss amount, and prose root cause, with PoCs
replaying calldata at `EXPLOIT_BLOCK - 1` and numeric assertions preserved
verbatim (e.g. `assertApproxEqAbs(drained, 190_155_976393, 1e6)`).

The live pinned-commit ingest against real upstream bytes is OWNER/RUNNER-
owned and runs after verification; that run is the byte-fidelity proof.

Layouts covered (one file each):
- `2022-03/Euler_exp.sol` — full card: tx hash, block (header + constant),
  attacker EOA, victim + harness labels, loss with token, multi-line root
  cause, verbatim numeric assertions.
- `2022-10/ATeam_exp.sol` — addresses only via `vm.label(...)` in the body;
  no loss line; single-line root cause.
- `2023-01/Minimal_exp.sol` — minimal card: tx hash + block anchor only.
- `2023-05/Nimbus_flashloan_exp.sol` — URL-embedded tx hash, token-less
  loss, underscored incident stem (`Nimbus_flashloan`).
- `2023-08/Orion_reentrancy_exp.sol` — block-comment (`/* ... */`) header
  layout, `Attacker wallet`/`Victim contract`/`Amount` label spellings.
- `2024-02/Sentiment_exp.sol` — attacker-only labels, USD loss, and an
  `&&` shell chain in a build note (shuvon_amp_rewrite probe).
- `2022-05/nounderscore.sol` — irregular: missing `_exp` suffix.
- `2022-13/BadMonth_exp.sol` — irregular: invalid month directory.
- `2022-06/Weird_exp.sol` — irregular: non-UTF-8 bytes.
- `Academy/**` — skipped entirely by `iter_exploit_files`.
