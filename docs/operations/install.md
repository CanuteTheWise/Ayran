# Install Ayran

Ayran installs from Windows-built archives into a selected WSL ext4 prefix. Active journals and SQLite never run on DrvFS.

## Layer versus Complete

**Ayran Layer** attaches beside an externally owned Prime 0.7.2. It does not copy, patch, upgrade, or remove that Prime. Install with `--layer --prime <path>`.

**Ayran Complete** installs an Ayran-owned versioned prefix that contains unmodified pinned Prime 0.7.2 plus Ayran. It never uses or removes a pre-existing Prime. Install with `--complete`.

Neither mode copies, upgrades, or removes Foundry, Slither, solc, or other WSL tools. Adapters detect them.

After Layer/Complete install, attach the package with `prime-agent package install <ayran-pkg> --local` in the audit workspace. Start a session with `prime-agent --ayran`. The Target Graph is pinned to that folder ([session.md](session.md)). Bind scope and arm injection as in [scope.md](scope.md).

## WSL selection

The installer must see a WSL2 distribution with an ext4 install and state root. The distribution name is chosen at install time. It is not hardcoded.

## Python

The sidecar uses the pinned Ayran Python package (jsonschema, pydantic, referencing, rfc8785). Complete may stage a managed `uv` environment under the versioned prefix. Layer uses the operator's compatible Python 3.11+ inside WSL. No install step requires network.

## Commands

```text
install-ayran.sh --layer --prime /path/to/prime --prefix ~/.local/ayran
install-ayran.sh --complete --prefix ~/.local/ayran
install-ayran.sh --layer --prime /path/to/prime --dry-run
ayran release install --layer --prime <path> --prefix <prefix>
ayran release install --complete --prefix <prefix>
ayran release validate --path dist/ayran-layer-0.1.6.tar.gz
```

`--dry-run` prints the exact plan (created paths, Prime classification, no Windows writes outside `dist`/explicit reports) and makes no changes.

## Receipts

Every applied install writes a machine-readable receipt under `<prefix>/receipts/`. The receipt lists only paths Ayran created, the versioned prefix, the atomic `current` pointer, and whether Prime is observed-external (Layer) or created-bundled-under-prefix (Complete).

## Rollback and uninstall

```text
ayran release rollback --receipt <receipt>
ayran release uninstall --receipt <receipt>
```

Rollback restores the prior pointer and removes only the versioned prefix named in the receipt. Uninstall removes only receipt-listed paths. Neither command removes externally owned Prime or tools. Complete may remove only its private Prime prefix.
