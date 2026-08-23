# Troubleshooting

## `ayran doctor`

`ayran doctor` checks Prime version/commit compatibility, WSL/ext4 placement, Python, extension load, sidecar handshake, schema/migration versions, graph integrity, tool manifests, resource headroom, and socket permissions. It does not send target content.

Interpret `doctor_status`:

- `healthy` — all checks passed.
- `failed` — read `checks` for the first failed invariant. Do not start a run.

## First session (`prime-agent --ayran`)

`--ayran` starts the sidecar, **reattaches this folder's Target Graph** (or
creates one), and auto-binds scope from the workspace layout (`src` /
`contracts` / nearby `.sol` / `.`). It does not inject audit context
packs until `/ayran:activate`. Override with `--ayran-manifest`, `AYRAN_SCOPE`,
or `.ayran/scope.json`. `AYRAN_FRESH=1` starts an empty graph.

`no scope manifest is loaded; fail closed` should not happen on a current
`--ayran` session. If it does, the Layer prefix is stale — refresh from the
Ayran tree. See [scope.md](scope.md).

## Graph did not survive `/quit`

Same folder, new `prime-agent --ayran`, should keep the same `run_id` in
`.ayran/engagement.json`. Mapping lives in that run, not in the Prime chat.

If it looks empty:

- `/ayran:activate` was not run in **this** Prime session (packs off; the
  graph is still on disk).
- `AYRAN_FRESH=1` or `ayran start --fresh` minted a new empty graph.
- The pin exists but `stream.json` is gone — Ayran treats that as stale and
  starts a new run.
- The clone is on DrvFS: journals are under `~/.local/state/ayran/runs/<id>`.
  Wiping WSL home loses them even if `.ayran/engagement.json` remains.

## Common error codes

| Code | Meaning | Operator action |
|---|---|---|
| `CONFIG` | malformed or weakening configuration | fix the layer that introduced the key |
| `COMPATIBILITY` | Prime/platform/tool lock mismatch | attach a tested Prime 0.7.2 or use Complete |
| `POLICY` / `SCOPE` / `PERMISSION` | denied action | change scope explicitly; do not retry unchanged |
| `RESOURCE` / `RESOURCE_EXHAUSTED` | disk, RSS, or budget | free space or reduce scope |
| `JOURNAL_CORRUPT` | canonical journal suffix invalid | freeze writes; copy journal; do not truncate |
| `PROJECTION_CORRUPT` | disposable SQLite | rebuild from the journal |
| `SEALED_LEAKAGE` | evaluation fixtures in Global/Learning | evaluation is invalid; do not promote |
| `URL_CLOSURE_INCOMPLETE` | Complete deps still have URL indirection | rebuild Complete from the pinned manifest |
| `PREREGISTRATION_REQUIRED` | live eval launch without a journaled signed sheet | run `ayran eval preregister --manifest ... --results-root ...` first |
| `PREREGISTRATION_MISMATCH` | sheet edited after signing (hash changed) | restore the signed content or preregister anew; never relabel |
| `PAUSE_ACTIVE` | eval kill-switch flag present | remove `<results-root>/eval.pause` (`ayran eval pause` wrote it) to resume |
| `CREDENTIAL_UNENROLLED` | credential-dependent call before key enrollment | extension enrolls on activate; headless harnesses must enroll explicitly |
| `LIVE_TRANSPORT_UNCONFIGURED` | live transport used before owner enablement | configure deliberately; ships disabled by design |

## Sidecar lifecycle (crash, orphan, manual relaunch)

The sidecar is a plain process: it dies with its parent unless daemonized, and a
stale socket file does not mean a live service.

```bash
# Relaunch an existing run in place (same run id, state root, socket, token):
ayran service --run <run_id> --state-root <state_root> \
              --socket <path>.sock --token-file <path>.token &
```

All four values come from the original `ayran start` receipt. After relaunch, verify
with a ping through the authenticated client before trusting it. A stale lease is
reclaimed by `ayran recover --run <id>`; interactive `/quit` remains the intended
clean shutdown. A second `prime-agent --print` client can look hung while the owner's
daemon still holds the worker — do not force-kill the daemon unprompted.

## Evaluation kill switch

`ayran eval pause --results-root <dir>` writes `eval.pause`. The runner honors it
between launches (`paused_operator`) and refuses new sessions while set. Delete the
flag file to resume; cap exhaustion pauses identically (`paused_cap`) and is disclosed
in the session manifest.

## Diagnose → bundle

```text
ayran diagnose --run RUN_ID --bundle PATH
```

The bundle is redacted and content-addressed. It contains configuration provenance, manifests, versions, logs, graph integrity, event ranges, process metadata, and checksums. Target artifacts are omitted unless explicitly included.

## Support bundle contents

Configuration hashes, compatibility locks, schema/migration versions, journal cursor and integrity, process identity tuples, tool receipts (detect-only), and the doctor report. No seeded secrets.
