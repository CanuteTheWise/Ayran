"""C3 map-builder enrichment: body-scoped WRITES, rich value-flow, map_target chain.

Named exits T1-T5 run on Windows (in-process dispatcher; no wsl_ext4).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from ayran.api.client import ClientError
from ayran.artifacts.store import ArtifactStore
from ayran.bridge.handler import build_dispatcher
from ayran.config.models import EffectiveConfig
from ayran.context.lenses import coupled_state_pairs, money_map_signaled
from ayran.context.queries import OntologyQueries, snapshot_view
from ayran.process.supervisor import ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from m3_fixtures import scope_value
from m5_fixtures import RUN_ID
from m6_fixtures import open_store

ENROLLMENT_KEY = b"c3-enrollment-key-32-bytes-aaaaaaa"[:32]

VAULT_FIXTURE = """
pragma solidity ^0.8.20;

contract EnrichedVault {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public constant FEE = 1;
    address public immutable FACTORY;

    constructor() {
        owner = msg.sender;
        FACTORY = msg.sender;
    }

    receive() external payable {}

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        _mint(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function steal() external {
        balances[msg.sender] = balances[msg.sender] + 1;
    }

    function sweepToken(address token, uint256 amount) external {
        token.safeTransfer(owner, amount);
    }

    function echo(uint256 value) external view returns (uint256) {
        uint256 amount = value;
        uint256 owner = amount;
        return owner;
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

QUIET_FIXTURE = """
pragma solidity ^0.8.20;

contract Quiet {
    uint256 public total;

    function getTotal() external view returns (uint256) {
        return total;
    }
}
"""


class _InProcessClient:
    def __init__(self, dispatcher: Any) -> None:
        self._dispatcher = dispatcher
        self.timeout = 10.0

    def call(self, method: str, **params: Any) -> Any:
        params.pop("token", None)
        try:
            return self._dispatcher.dispatch(method, params)
        except PermissionError as error:
            raise ClientError({"code": -32004, "message": str(error)}) from error


def _sidecar(tmp_path: Path) -> tuple[Any, Any]:
    store = open_store(tmp_path / "graph")
    config = EffectiveConfig(state_root=str(tmp_path / "state"))
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    (tmp_path / "scope.json").write_text(json.dumps(scope_value()), encoding="utf-8")
    logger = StructuredLogger(logs / "runtime.jsonl", run_id=RUN_ID, component="ayran.test")
    artifact_store = ArtifactStore(tmp_path / "artifacts", allow_unsafe_filesystem=True)
    supervisor = ProcessSupervisor(
        tmp_path / "processes", run_id=RUN_ID, logger=logger, artifact_store=artifact_store
    )
    dispatcher = build_dispatcher(
        run_id=RUN_ID,
        config=config,
        store=store,
        logger=logger,
        artifact_store=artifact_store,
        process_supervisor=supervisor,
        receipt={"schema_version": "1.0.0", "run_id": RUN_ID, "run_state": "running"},
        state_root=tmp_path / "state",
        run_root=tmp_path,
    )
    return dispatcher, store


@pytest.fixture()
def engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    import ayran.skill.verbs as verbs

    dispatcher, store = _sidecar(tmp_path)
    enrolled = dispatcher.dispatch(
        "credentials.enroll", {"key_b64": base64.b64encode(ENROLLMENT_KEY).decode("ascii")}
    )
    assert enrolled["accepted"] is True
    monkeypatch.setattr(verbs, "_connect", lambda: _InProcessClient(dispatcher))
    try:
        yield dispatcher
    finally:
        store.close()


def _node_name(node: dict[str, Any]) -> str:
    for item in node.get("properties") or []:
        if item.get("name") == "name":
            return str(item.get("value") or "")
    return ""


def _view(dispatcher: Any) -> Any:
    return snapshot_view(OntologyQueries(store=dispatcher.store), run_id=RUN_ID)


def _writes_to(view: Any, state: str) -> set[str]:
    names = {str(node.get("node_id") or ""): _node_name(node) for node in view.nodes}
    writers: set[str] = set()
    for edge in view.edges:
        if edge.get("edge_type") != "WRITES":
            continue
        if names.get(str(edge.get("target_id") or "")) == state:
            writers.add(names.get(str(edge.get("source_id") or ""), ""))
        elif names.get(str(edge.get("source_id") or "")) == state:
            writers.add(names.get(str(edge.get("target_id") or ""), ""))
    return writers


def _inner_pack(mapped: dict[str, Any]) -> dict[str, Any]:
    pack = mapped.get("pack") or {}
    inner = pack.get("pack")
    return inner if isinstance(inner, dict) else pack


def _section(mapped: dict[str, Any], title: str) -> dict[str, Any] | None:
    for item in _inner_pack(mapped).get("sections") or []:
        if item.get("title") == title:
            return item
    return None


def test_coupled_pairs_render_on_real_fixture(engagement: Any) -> None:
    import ayran.skill.verbs as verbs

    mapped = verbs.map_target(source_text=VAULT_FIXTURE)
    assert mapped["schema_version"] == "1.0.0"
    view = _view(engagement)
    assert _writes_to(view, "balances") == {"deposit", "withdraw", "steal"}
    assert _writes_to(view, "owner") == {"constructor"}
    assert "constructor" not in _writes_to(view, "balances")
    assert "sweepToken" not in _writes_to(view, "balances")
    assert "echo" not in _writes_to(view, "balances")
    assert not _writes_to(view, "FEE")
    assert not _writes_to(view, "FACTORY")
    pairs = coupled_state_pairs(view)
    balances = next(item for item in pairs if item["state_name"] == "balances")
    assert len(balances["function_ids"]) == 3
    blob = " ".join(balances["mutation_status"])
    assert "deposit" in blob and "withdraw" in blob and "steal" in blob
    section = _section(mapped, "Coupled-state pair inventory")
    assert section is not None
    content = str(section["content"])
    assert "balances" in content
    assert "deposit" in content and "withdraw" in content and "steal" in content


def test_money_map_renders_rich_payload_on_real_fixture(engagement: Any) -> None:
    import ayran.skill.verbs as verbs

    mapped = verbs.map_target(source_text=VAULT_FIXTURE)
    view = _view(engagement)
    assert isinstance(view.maps.get("value_flow"), dict) and view.maps["value_flow"]
    assert money_map_signaled(view) is True
    payload = view.maps["value_flow"]
    assert "invariants" not in payload
    section = _section(mapped, "Money-map summary")
    assert section is not None
    content = str(section["content"])
    lines = content.split("\n")
    assert len(lines) <= 200
    assert "(truncated at 200-line cap)" not in content
    assert "deposit" in content
    assert "receive" in content
    assert "balances" in content
    assert "denominator" in content or "denominator" in json.dumps(payload.get("totals") or [])
    assert "mint" in content


def test_absence_is_honest(engagement: Any) -> None:
    import ayran.skill.verbs as verbs

    mapped = verbs.map_target(source_text=QUIET_FIXTURE)
    view = _view(engagement)
    writes = [edge for edge in view.edges if edge.get("edge_type") == "WRITES"]
    assert writes == []
    assert coupled_state_pairs(view) == []
    assert money_map_signaled(view) is False
    titles = [str(item.get("title") or "") for item in _inner_pack(mapped).get("sections") or []]
    assert "Money-map summary" not in titles
    assert "Coupled-state pair inventory" not in titles


def test_rebuild_is_idempotent(engagement: Any) -> None:
    import ayran.skill.verbs as verbs

    verbs.map_target(source_text=VAULT_FIXTURE)
    first = _view(engagement)
    first_writes = [edge for edge in first.edges if edge.get("edge_type") == "WRITES"]
    first_nodes = list(first.nodes)
    first_ids = sorted(str(edge.get("edge_id") or "") for edge in first_writes)
    # A second full map_target re-seeds coverage cells and collides on the
    # existing persist command key (pre-existing, out of C3 bounds). Graph
    # objects dedupe by node_id/edge_id; rebuild data_flow + value_flow.
    engagement.dispatch(
        "maps.build",
        {"map_type": "data_flow", "source_text": VAULT_FIXTURE, "persist": True},
    )
    engagement.dispatch(
        "maps.build",
        {"map_type": "value_flow", "source_text": VAULT_FIXTURE, "persist": True},
    )
    second = _view(engagement)
    second_writes = [edge for edge in second.edges if edge.get("edge_type") == "WRITES"]
    second_ids = sorted(str(edge.get("edge_id") or "") for edge in second_writes)
    assert len(second_writes) == len(first_writes)
    assert len(second.nodes) == len(first_nodes)
    assert second_ids == first_ids
    assert len(set(second_ids)) == len(second_ids)


def test_census_fields_still_present(engagement: Any) -> None:
    import ayran.skill.verbs as verbs

    mapped = verbs.map_target(source_text=VAULT_FIXTURE)
    blob = "\n".join(
        str(item.get("content") or "") for item in _inner_pack(mapped).get("sections") or []
    )
    assert "census_total" in blob
    assert "census_examined" in blob
    assert "unexamined" in blob
