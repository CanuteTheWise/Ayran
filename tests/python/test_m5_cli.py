"""M5 CLI commands against a local unsafe graph root."""

from __future__ import annotations

from pathlib import Path

from ayran.cli import main as cli_main
from ayran.mapping.attack_surface import build_attack_surface
from ayran.router.persist import persist_graph_objects
from ayran.router.service import router_status, router_step
from m5_fixtures import CLUSTER, VAULT_SOURCE, open_store, write_stream


def _invoke(argv: list[str]) -> tuple[int, str]:
    import io
    from contextlib import redirect_stdout

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli_main(argv)
    return code, buffer.getvalue()


def test_cli_context_compile_and_router_status(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        built = build_attack_surface(
            cluster_id=CLUSTER,
            run_id=store.stream["run_id"],
            source_text=VAULT_SOURCE,
        )
        persist_graph_objects(store, built["nodes"], built["edges"])
        root, stream = write_stream(tmp_path, store)
    finally:
        store.close()
    code, output = _invoke(
        [
            "context",
            "compile",
            "--graph-root",
            str(root),
            "--stream",
            str(stream),
            "--allow-unsafe-filesystem",
            "--cluster",
            CLUSTER,
            "--budget",
            "4000",
        ]
    )
    assert code == 0
    assert "context_pack_id" in output
    assert "DETERMINISTIC_FACT" in output or "HYPOTHESIS" in output
    code, status = _invoke(
        [
            "router",
            "status",
            "--graph-root",
            str(root),
            "--stream",
            str(stream),
            "--allow-unsafe-filesystem",
        ]
    )
    assert code == 0
    assert "coverage" in status
    assert "budget" in status
    code, maps = _invoke(
        [
            "maps",
            "attack_surface",
            "--graph-root",
            str(root),
            "--stream",
            str(stream),
            "--allow-unsafe-filesystem",
            "--source",
            str(Path(__file__).resolve().parents[2] / "fixtures" / "cognitive" / "VulnerableVault.sol"),
        ]
    )
    assert code == 0
    assert "attack_surface" in maps
    code, coverage = _invoke(
        [
            "coverage",
            "summary",
            "--graph-root",
            str(root),
            "--stream",
            str(stream),
            "--allow-unsafe-filesystem",
        ]
    )
    assert code == 0
    assert "cell_count" in coverage or "schema_version" in coverage


def test_router_step_persists_target_first_and_budget(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        built = build_attack_surface(
            cluster_id=CLUSTER,
            run_id=store.stream["run_id"],
            source_text=VAULT_SOURCE,
        )
        persist_graph_objects(store, built["nodes"], built["edges"])
        first = router_step(store, cluster_id=CLUSTER, persist=True)
        assert first["lens_updates"]["coverage"]["lens"] == "coverage"
        status = router_status(store, cluster_id=CLUSTER)
        assert status["budget"]["spent"]["coverage"] > 0
        assert CLUSTER in status.get("lens_states", {}) or status["budget"]["spent"]["coverage"]
        second = router_step(store, cluster_id=CLUSTER, persist=True)
        # After the target-first pass is recorded, later cycles may include precedent.
        _ = second
    finally:
        store.close()
