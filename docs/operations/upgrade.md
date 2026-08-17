# Upgrade

Ayran upgrades are pointer switches, not in-place rewrites.

## Package pointer

Each install stages a versioned prefix (`<prefix>/versions/<version>`) and atomically updates `<prefix>/current`. Historical runs keep the corpus, routing, and tool pins they opened.

## Procedure

1. Build Layer or Complete (`ayran release build --layer` or `--complete`).
2. Validate the archive (`ayran release validate --path ...`).
3. Install beside the previous prefix. Health checks run before the pointer moves.
4. Confirm `ayran doctor`.

## Rollback

```text
ayran release rollback --receipt <new-install-receipt>
```

This restores the prior pointer and removes only the new versioned prefix. Externally owned Prime and tools are untouched.

## Corpus and routing pins

Every run records the Global corpus pointer and Learning routing policy it used. Rolling back the package does not rewrite those historical pins. To roll back knowledge or routing, use `ayran knowledge` / `ayran learning rollback` on their own receipts.
