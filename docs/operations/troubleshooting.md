# Troubleshooting

## `ayran doctor`

`ayran doctor` checks Prime version/commit compatibility, WSL/ext4 placement, Python, extension load, sidecar handshake, schema/migration versions, graph integrity, tool manifests, resource headroom, and socket permissions. It does not send target content.

Interpret `doctor_status`:

- `healthy` — all checks passed.
- `failed` — read `checks` for the first failed invariant. Do not start a run.

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

## Diagnose → bundle

```text
ayran diagnose --run RUN_ID --bundle PATH
```

The bundle is redacted and content-addressed. It contains configuration provenance, manifests, versions, logs, graph integrity, event ranges, process metadata, and checksums. Target artifacts are omitted unless explicitly included.

## Support bundle contents

Configuration hashes, compatibility locks, schema/migration versions, journal cursor and integrity, process identity tuples, tool receipts (detect-only), and the doctor report. No seeded secrets.
