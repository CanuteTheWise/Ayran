"""R5 — S9.5: SIGKILL crash/resume with zero lost events (spec §9).

Named binary check:
``test_sigkill_mid_tool_run_zero_loss``

Follows the existing SIGKILL harness pattern (``tests/python/test_m2_sigkill.py``
and ``tests/python/graph_crash_worker.py`` — the append-command builder and
stream identity are REUSED by import; the scenario worker lives in this module
and runs as a real subprocess so ``kill -9`` is genuine). Requires WSL ext4;
auto-skips on Windows, growing the sanctioned skip set 54 -> 55 BY THIS TEST
ONLY.

Scenario: >=100 acknowledged journal events seeded; an adapter spool entry (a
supervised adapter process record) is left incomplete; SIGKILL hits the
worker (sidecar stand-in) and the adapter mid-run. Restart replays the journal
via ``graph/recovery.py``; the projection equals the last committed checkpoint;
hash-chain verification passes; the lease is reclaimed via ``graph/leases.py``
and the interrupted tool run is finalized as interrupted — never ``completed``
; the reconstructed context pack sections are byte-equal to the pre-kill
capture.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

SELECTED_ROOT = os.environ.get("AYRAN_WSL_EXT4_ROOT")
SIGKILL = getattr(signal, "SIGKILL", 9)
RUN_ID = "run_01K000000000000000000000R5"

pytestmark = [
    pytest.mark.wsl_ext4,
    pytest.mark.resilience,
    pytest.mark.skipif(not SELECTED_ROOT, reason="AYRAN_WSL_EXT4_ROOT selects a safe ext4 base"),
]


def _worker_argv(action: str, root: Path, *extra: str) -> list[str]:
    src = str(Path(__file__).resolve().parents[2] / "skills" / "ayran" / "src")
    tests = str(Path(__file__).resolve().parent)
    bootstrap = (
        "import sys; "
        f"sys.path.insert(0, {src!r}); "
        f"sys.path.insert(0, {tests!r}); "
        "from test_r5_crash_resume import worker_main; "
        "raise SystemExit(worker_main())"
    )
    return [sys.executable, "-c", bootstrap, action, "--root", str(root), *extra]


def _worker(action: str, root: Path, *extra: str) -> dict:
    completed = subprocess.run(
        _worker_argv(action, root, *extra),
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return json.loads(completed.stdout)


def test_sigkill_mid_tool_run_zero_loss() -> None:
    assert SELECTED_ROOT is not None
    base_root = Path(SELECTED_ROOT).resolve(strict=True)
    probe = subprocess.run(
        ["findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(base_root)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert probe.stdout.strip() == "ext4"
    root = Path(tempfile.mkdtemp(prefix="r5-crash-", dir=base_root))
    try:
        ready = root / "fault.ready"
        ready.unlink(missing_ok=True)
        process = subprocess.Popen(
            _worker_argv("seed", root, "--run-id", RUN_ID, "--fault", "mid_tool_run"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 60
        while not ready.is_file() and time.monotonic() < deadline:
            if process.poll() is not None:
                out, err = process.communicate()
                pytest.fail(f"seed worker exited before the fault point: {out}\n{err}")
            time.sleep(0.05)
        assert ready.read_text(encoding="utf-8") == "mid_tool_run"

        adapter = json.loads((root / "state" / "runs" / RUN_ID / "adapter-entry.json").read_text(encoding="utf-8"))
        # SIGKILL the adapter process group FIRST (the interrupted tool run),
        # then the worker (the sidecar stand-in) holding the lease mid-run.
        os.killpg(int(adapter["pgid"]), SIGKILL)
        os.killpg(process.pid, SIGKILL)
        process.wait(timeout=10)
        assert process.returncode == -SIGKILL
        ready.unlink(missing_ok=True)

        # Restart: replay + lease reclaim + process reconciliation.
        recovered = _worker("recover", root, "--run-id", RUN_ID)
        assert recovered["lease_reclaimed"] is True
        interrupted = [
            entry
            for entry in recovered["reconciled_processes"]
            if entry["process_uid"] == adapter["process_uid"]
        ]
        assert interrupted, "the interrupted adapter spool entry was not reconciled"
        final_state = str(interrupted[0]["final_state"])
        # The interrupted tool run is finalized as interrupted (absent owner,
        # pid-absent reason) — NEVER completed.
        assert final_state in {"exited", "signalled", "zombie_reaped", "killed_grace_expired"}
        assert final_state != "completed"

        # Zero lost events: hash chain verifies, projection == last committed
        # checkpoint, every acknowledged event present post-restart.
        prekill_checkpoint = json.loads(
            (root / "state" / "runs" / RUN_ID / "checkpoint-prekill.json").read_text(encoding="utf-8")
        )
        report = _worker("verify", root, "--run-id", RUN_ID)
        assert report["status"] == "ok"
        assert report["issues"] == []
        assert report["journal_cursor"] == report["projection_cursor"]
        assert report["journal_cursor"] == prekill_checkpoint["journal_cursor"]
        assert report["verified_events"] >= 100

        # Reconstructed context pack sections are byte-equal pre/post restart.
        post = _worker("pack", root, "--run-id", RUN_ID)
        assert post["pack_written"] is True
        prekill_bytes = (root / "state" / "runs" / RUN_ID / "pack-sections-prekill.bytes").read_bytes()
        restarted_bytes = (root / "state" / "runs" / RUN_ID / "pack-sections-restart.bytes").read_bytes()
        assert restarted_bytes == prekill_bytes
    finally:
        import shutil

        resolved = root.resolve(strict=True)
        assert resolved.parent == base_root and resolved.name.startswith("r5-crash-")
        shutil.rmtree(resolved)


# --- scenario worker (runs as a REAL subprocess; killed with SIGKILL) ---------


def worker_main() -> int:  # pragma: no cover - exercised via subprocess
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["seed", "recover", "verify", "pack"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--run-id", default=RUN_ID)
    parser.add_argument("--fault")
    parser.add_argument("--events", type=int, default=120)
    arguments = parser.parse_args()

    from ayran.config.models import EffectiveConfig
    from ayran.runtime.paths import process_root as _process_root
    from ayran.runtime.paths import run_root as _run_root

    state_root = arguments.root / "state"
    base = _run_root(state_root, arguments.run_id)
    base.mkdir(parents=True, exist_ok=True)
    config = EffectiveConfig(state_root=str(state_root))

    if arguments.action == "recover":
        from ayran.runtime.recover import recover_run

        result = recover_run(config, arguments.run_id, state_root)
        print(json.dumps(result, default=str))
        return 0

    from ayran.graph.recovery import GraphStore
    from graph_crash_worker import HASH_A, command, stream_identity

    stream = stream_identity()
    (base / "stream.json").write_text(json.dumps(stream), encoding="utf-8")
    store = GraphStore(base / "graph", stream, allow_unsafe_filesystem=True)

    try:
        if arguments.action == "seed":
            for ordinal in range(1, arguments.events + 1):
                store.append(command(ordinal))
            checkpoint = store.checkpoint(config_hash=HASH_A)
            (base / "checkpoint-prekill.json").write_text(json.dumps(checkpoint), encoding="utf-8")

            # Adapter spool entry left incomplete: a REAL supervised adapter
            # process whose record stays in state "running" across the kill.
            from ayran.artifacts.store import ArtifactStore
            from ayran.process.supervisor import ProcessBudget, ProcessSupervisor
            from ayran.runtime.logs import StructuredLogger

            logger = StructuredLogger(
                base / "logs" / "runtime.jsonl",
                run_id=arguments.run_id,
                component="ayran.r5-worker",
            )
            artifact_store = ArtifactStore(base / "artifacts", allow_unsafe_filesystem=True)
            supervisor = ProcessSupervisor(
                _process_root(state_root, arguments.run_id),
                run_id=arguments.run_id,
                logger=logger,
                artifact_store=artifact_store,
            )
            entry = supervisor.spawn(
                ("/bin/sh", "-c", "sleep 300"),
                budget=ProcessBudget(wall_seconds=600, graceful_stop_seconds=1),
                scope_hash=HASH_A,
                actor={"kind": "tool", "id": "ayran.r5-crash", "version": "1.0.0"},
            )
            (base / "adapter-entry.json").write_text(
                json.dumps(
                    {
                        "process_uid": entry.process_uid,
                        "pid": entry.pid,
                        "pgid": entry.pgid,
                    }
                ),
                encoding="utf-8",
            )

            # Pre-kill context pack snapshot (section JSON bytes).
            from ayran.router.service import compile_pack

            pack = compile_pack(
                store,
                token_budget=4000,
                purpose="crash-resume",
                role="root-auditor",
            )
            sections_bytes = json.dumps(
                pack["pack"]["sections"], sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            (base / "pack-sections-prekill.bytes").write_bytes(sections_bytes)

            # Fault point: hang mid-run (lease held, spool entry incomplete).
            ready = arguments.root / "fault.ready"
            ready.write_text(str(arguments.fault or "mid_tool_run"), encoding="utf-8")
            while True:
                time.sleep(60)

        if arguments.action == "verify":
            store.replay()
            report = store.verify()
            print(json.dumps(report, default=str))
            return 0

        if arguments.action == "pack":
            from ayran.router.service import compile_pack

            pack = compile_pack(
                store,
                token_budget=4000,
                purpose="crash-resume",
                role="root-auditor",
            )
            sections_bytes = json.dumps(
                pack["pack"]["sections"], sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            (base / "pack-sections-restart.bytes").write_bytes(sections_bytes)
            print(json.dumps({"pack_written": True}))
            return 0
        raise SystemExit(f"unknown action {arguments.action}")
    finally:
        store.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(worker_main())
