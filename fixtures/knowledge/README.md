# R4 corpus-ingestion fixtures

All bytes under this tree are TEST FIXTURES, not upstream captures.

- `defihacklabs/samples/` — format-faithful reconstructed DeFiHackLabs
  header cards (clearly labeled synthetic; see that directory's README).
  The live pinned-commit ingest is owner-run after verification.
- `krait/deep-sample/` — synthetic Krait check blocks defining the deep-
  ingest block contract (`---`-separated YAML check blocks with optional
  solc ranges, pattern signatures, and token standards). The owner's
  845-check pinned snapshot arrives later and must parse with the same
  parser.

None of these fixtures are compiled or executed by Ayran (spec 11.3 rule 6).
