# Deterministic WSL staging

`scripts/stage-wsl.ps1` discovers registered WSL distributions and requires an explicit selection when discovery is ambiguous. It passes arguments directly to `scripts/stage_wsl.py` inside the selected distribution; it does not construct shell command strings.

The helper resolves the staging base inside that distribution and fails unless `findmnt` reports ext4. `Plan` is read-only and emits a sorted per-file SHA-256 manifest plus a content-derived stage name. `Stage` refuses to overwrite an existing child, copies regular files only, verifies every destination byte, and writes an authenticated receipt/marker pair.

Both plans carry the canonical Ayran M1 payload plus the Layer, Complete, and pinned vendor control manifests so either staged tree can run the complete M0+M1 verification suite. The selected distribution mode controls the receipt and content identity. Only Complete adds the verified unmodified Prime v0.7.2 release archive. Neither mode installs or invokes Prime, and neither mode copies, upgrades, or removes external tools. Active journals, projections, leases, sockets, and test diagnostics are forbidden from the payload.

`Cleanup` requires the exact Linux base and exact child paths. It verifies ext4, direct-child ancestry, the content-derived name shape, regular receipt/marker files, the receipt hash, and the receipt ownership claim before removing that child. It never removes the base, a discovered Prime installation, or any external tool.
