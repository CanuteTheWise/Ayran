"""M5 maps and coverage grid transitions."""

from __future__ import annotations

import json
from pathlib import Path

from ayran.mapping.attack_surface import build_attack_surface
from ayran.mapping.authority import build_authority
from ayran.mapping.control_flow import build_control_flow
from ayran.mapping.coverage import CoverageGrid, CoverageTransitionError
from ayran.mapping.data_flow import build_data_flow
from ayran.mapping.temporal import build_temporal
from ayran.mapping.value_flow import build_value_flow
from m5_fixtures import CLUSTER, CREATED, RUN_ID, SLITHER_VAULT, VAULT_SOURCE

ROOT = Path(__file__).resolve().parents[2]


def test_coverage_forward_only_transitions() -> None:
    grid = CoverageGrid(cluster_id=CLUSTER)
    grid.ensure("entry_points", "withdraw", run_id=RUN_ID, created_at=CREATED, risk=40)
    grid.transition("entry_points", "withdraw", "in_progress")
    grid.transition("entry_points", "withdraw", "lead_found")
    try:
        grid.transition("entry_points", "withdraw", "unexamined")
        raised = False
    except CoverageTransitionError:
        raised = True
    assert raised
    grid.transition("entry_points", "withdraw", "unexamined", invalidate=True)
    summary = grid.get_coverage_summary()
    assert summary["cell_count"] == 1
    uncovered = grid.get_risk_weighted_uncovered()
    assert uncovered


def test_all_five_plus_attack_surface_maps() -> None:
    kwargs = {
        "cluster_id": CLUSTER,
        "run_id": RUN_ID,
        "created_at": CREATED,
        "source_text": VAULT_SOURCE,
        "slither_json": SLITHER_VAULT,
        "locator": "fixtures/cognitive/VulnerableVault.sol",
    }
    surface = build_attack_surface(**kwargs)
    control = build_control_flow(**{key: value for key, value in kwargs.items() if key != "solc_json"})
    data = build_data_flow(**{key: value for key, value in kwargs.items() if key != "solc_json"})
    value = build_value_flow(**{key: value for key, value in kwargs.items() if key != "solc_json"})
    auth = build_authority(**{key: value for key, value in kwargs.items() if key != "solc_json"})
    temporal = build_temporal(**{key: value for key, value in kwargs.items() if key != "solc_json"})
    assert surface["entry_points"]
    assert any(item["name"] == "withdraw" for item in surface["functions"])
    assert control["nodes"]
    assert data["nodes"]
    assert value["payload"]["cluster_id"] == CLUSTER
    assert "owner" in auth["roles"] or auth["nodes"]
    assert temporal["patterns"] or temporal["nodes"]
    for built in (surface, control, data, value, auth, temporal):
        assert built["map_type"]
        payload = json.dumps(built["payload"], sort_keys=True)
        assert "cluster_id" in payload


def test_attack_surface_from_slither_fixture() -> None:
    solc = json.loads((ROOT / "fixtures" / "tool-output" / "solc-success.json").read_text(encoding="utf-8"))
    built = build_attack_surface(
        cluster_id=CLUSTER,
        run_id=RUN_ID,
        slither_json=SLITHER_VAULT,
        solc_json=solc,
        source_text=VAULT_SOURCE,
    )
    names = {item["name"] for item in built["functions"]}
    assert "withdraw" in names
    assert "greet" in names or "deposit" in names
