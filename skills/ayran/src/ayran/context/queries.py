"""Typed Target/Global/Learning query services. Sidecar-internal or UDS-backed."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from ayran.context.ids import DEFAULT_CLUSTER_ID, DEFAULT_RUN_ID, ZERO_HASH
from ayran.context.view import GraphView
from ayran.mapping.coverage import parse_cell_meta

ACTIVE_STATUSES = {
    "lead",
    "supported",
    "poc_worthy",
    "observed",
    "defect_pinned",
    "needs_missing_fact",
    "needs_reformulation",
}


def _latest_domain(store: Any, table: str, id_column: str) -> list[dict[str, Any]]:
    sql = (
        f"SELECT t.* FROM {table} t JOIN ("
        f"SELECT {id_column} AS id, MAX(revision) AS revision FROM {table} GROUP BY {id_column}"
        f") latest ON t.{id_column}=latest.id AND t.revision=latest.revision"
    )
    with store.projection.snapshot() as connection:
        records: list[dict[str, Any]] = []
        for row in connection.execute(sql).fetchall():
            payload = json.loads(row["object_json"])
            if isinstance(payload, dict):
                records.append(payload)
        return records


def _latest_nodes(store: Any) -> list[dict[str, Any]]:
    sql = """
        SELECT r.object_json FROM nodes n
        JOIN node_revisions r ON r.node_id=n.node_id AND r.revision=n.current_revision
        WHERE n.status != 'tombstoned'
        ORDER BY n.node_id
    """
    with store.projection.snapshot() as connection:
        records: list[dict[str, Any]] = []
        for row in connection.execute(sql).fetchall():
            payload = json.loads(row["object_json"])
            if isinstance(payload, dict):
                records.append(payload)
        return records


def _latest_edges(store: Any) -> list[dict[str, Any]]:
    sql = """
        SELECT r.object_json FROM edges e
        JOIN edge_revisions r ON r.edge_id=e.edge_id AND r.revision=e.current_revision
        WHERE e.status != 'tombstoned'
        ORDER BY e.edge_id
    """
    with store.projection.snapshot() as connection:
        records: list[dict[str, Any]] = []
        for row in connection.execute(sql).fetchall():
            payload = json.loads(row["object_json"])
            if isinstance(payload, dict):
                records.append(payload)
        return records


def _props(node: dict[str, Any]) -> dict[str, Any]:
    mapped: dict[str, Any] = {}
    for item in node.get("properties") or []:
        if isinstance(item, dict) and "name" in item:
            mapped[str(item["name"])] = item.get("value")
    return mapped


def _mechanism_card(node: dict[str, Any], props: dict[str, Any]) -> dict[str, Any]:
    predicates = props.get("applicability_predicates") or ""
    if isinstance(predicates, str):
        predicate_list = [item for item in predicates.split(",") if item]
    else:
        predicate_list = list(predicates) if isinstance(predicates, list) else []
    return {
        "id": node.get("node_id"),
        "title": props.get("title") or props.get("name") or "mechanism",
        "record_type": props.get("record_type") or "mechanism",
        "mechanism": props.get("mechanism"),
        "language": props.get("language"),
        "applicability_predicates": predicate_list,
        "trust_tier": props.get("trust_tier") or "curated_external",
        "provenance": node.get("provenance") or [],
        "historical_reference": True,
        "hard_negative": bool(props.get("hard_negative")),
    }


class OntologyQueries:
    """Async query facade. Local store is used inside the sidecar; client over UDS."""

    def __init__(self, *, store: Any | None = None, client: Any | None = None) -> None:
        if (store is None) == (client is None):
            raise ValueError("OntologyQueries requires exactly one of store or client")
        self.store = store
        self.client = client

    async def _call(self, method: str, **params: Any) -> Any:
        if self.client is not None:
            return await asyncio.to_thread(self.client.call, method, **params)
        handler = getattr(self, f"_{method.replace('.', '_')}", None)
        if handler is None:
            raise LookupError(method)
        return handler(params)

    async def _call_list(self, method: str, **params: Any) -> list[dict[str, Any]]:
        result = await self._call(method, **params)
        if not isinstance(result, list):
            raise TypeError(f"{method} expected a list")
        return [item for item in result if isinstance(item, dict)]

    async def _call_object(self, method: str, **params: Any) -> dict[str, Any] | None:
        result = await self._call(method, **params)
        if result is None:
            return None
        if not isinstance(result, dict):
            raise TypeError(f"{method} expected an object")
        return result

    def _require_store(self) -> Any:
        if self.store is None:
            raise RuntimeError("local query requires a GraphStore")
        return self.store

    async def get_active_hypotheses(self, cluster_id: str | None = None) -> list[dict[str, Any]]:
        return await self._call_list("ontology.get_active_hypotheses", cluster_id=cluster_id)

    def _ontology_get_active_hypotheses(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        cluster_id = params.get("cluster_id")
        rows = [
            item
            for item in _latest_domain(self._require_store(), "hypotheses", "hypothesis_id")
            if item.get("status") in ACTIVE_STATUSES
        ]
        if cluster_id:
            rows = [item for item in rows if cluster_id in (item.get("target_entities") or [])]
        return sorted(rows, key=lambda row: str(row.get("hypothesis_id")))

    async def get_hypothesis_by_id(self, hypothesis_id: str) -> dict[str, Any] | None:
        return await self._call_object("ontology.get_hypothesis_by_id", hypothesis_id=hypothesis_id)

    def _ontology_get_hypothesis_by_id(self, params: dict[str, Any]) -> dict[str, Any] | None:
        identifier = str(params.get("hypothesis_id") or "")
        for item in _latest_domain(self._require_store(), "hypotheses", "hypothesis_id"):
            if item.get("hypothesis_id") == identifier:
                return item
        return None

    async def get_coverage_grid(self, cluster_id: str) -> list[dict[str, Any]]:
        return await self._call_list("ontology.get_coverage_grid", cluster_id=cluster_id)

    def _ontology_get_coverage_grid(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        cluster_id = str(params.get("cluster_id") or "")
        rows = _latest_domain(self._require_store(), "coverage_cells", "coverage_cell_id")
        if cluster_id:
            filtered = []
            for item in rows:
                refs = item.get("target_refs") or []
                if cluster_id in refs or cluster_id in str(item.get("dimension") or ""):
                    filtered.append(item)
            rows = filtered
        return sorted(rows, key=lambda row: str(row.get("coverage_cell_id")))

    async def get_uncovered_cells(self, risk_threshold: int = 0) -> list[dict[str, Any]]:
        return await self._call_list("ontology.get_uncovered_cells", risk_threshold=risk_threshold)

    def _ontology_get_uncovered_cells(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        threshold = int(params.get("risk_threshold") or 0)
        uncovered: list[dict[str, Any]] = []
        for item in _latest_domain(self._require_store(), "coverage_cells", "coverage_cell_id"):
            status = item.get("status")
            if status in {"examined", "blocked", "accepted_residual_risk"}:
                continue
            meta = parse_cell_meta(str(item.get("examined_result") or ""))
            if meta.risk_score >= threshold and (
                meta.cell_state in {
                    "unexamined",
                    "in_progress",
                    "lead_found",
                    "hypothesis_active",
                }
                or status == "open"
            ):
                uncovered.append(item)
        return sorted(uncovered, key=lambda row: str(row.get("coverage_cell_id")))

    async def get_evidence_for_hypothesis(self, hypothesis_id: str) -> list[dict[str, Any]]:
        return await self._call_list(
            "ontology.get_evidence_for_hypothesis", hypothesis_id=hypothesis_id
        )

    def _ontology_get_evidence_for_hypothesis(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        hypothesis_id = str(params.get("hypothesis_id") or "")
        rows = []
        for item in _latest_domain(self._require_store(), "evidence", "evidence_id"):
            supports = item.get("supports") or []
            if hypothesis_id in supports:
                rows.append(item)
        return sorted(rows, key=lambda row: str(row.get("evidence_id")))

    async def get_tool_runs(
        self, capability_id: str | None = None, since: str | None = None
    ) -> list[dict[str, Any]]:
        return await self._call_list(
            "ontology.get_tool_runs", capability_id=capability_id, since=since
        )

    def _ontology_get_tool_runs(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        capability_id = params.get("capability_id")
        since = params.get("since")
        rows = _latest_domain(self._require_store(), "tool_runs", "tool_run_id")
        if capability_id:
            rows = [
                item
                for item in rows
                if item.get("capability_id") == capability_id or item.get("tool_name") == capability_id
            ]
        if since:
            rows = [item for item in rows if str(item.get("created_at") or "") >= str(since)]
        return sorted(rows, key=lambda row: str(row.get("tool_run_id")))

    async def get_dead_ends(self, cluster_id: str) -> list[dict[str, Any]]:
        return await self._call_list("ontology.get_dead_ends", cluster_id=cluster_id)

    def _ontology_get_dead_ends(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        cluster_id = str(params.get("cluster_id") or "")
        results: list[dict[str, Any]] = []
        for node in _latest_nodes(self._require_store()):
            if node.get("node_type") != "DeadEnd":
                continue
            props = _props(node)
            if cluster_id and props.get("cluster_id") not in {cluster_id, None, ""}:
                continue
            results.append(
                {
                    "id": node.get("node_id"),
                    "approach": props.get("approach") or "unspecified",
                    "reason": props.get("reason") or "rejected",
                    "cluster_id": props.get("cluster_id") or cluster_id,
                }
            )
        for item in _latest_domain(self._require_store(), "hypotheses", "hypothesis_id"):
            if item.get("status") in {"falsified", "parked"}:
                results.append(
                    {
                        "id": item.get("hypothesis_id"),
                        "approach": item.get("claim"),
                        "reason": str(item.get("status")),
                        "cluster_id": cluster_id,
                    }
                )
        return sorted(results, key=lambda row: str(row.get("id")))

    async def get_open_questions(self, cluster_id: str) -> list[dict[str, Any]]:
        return await self._call_list("ontology.get_open_questions", cluster_id=cluster_id)

    def _ontology_get_open_questions(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        cluster_id = str(params.get("cluster_id") or "")
        results: list[dict[str, Any]] = []
        for node in _latest_nodes(self._require_store()):
            if node.get("node_type") != "OpenQuestion":
                continue
            props = _props(node)
            results.append(
                {
                    "id": node.get("node_id"),
                    "question": props.get("question") or props.get("title") or "unspecified",
                    "cluster_id": props.get("cluster_id") or cluster_id,
                }
            )
        for item in _latest_domain(self._require_store(), "hypotheses", "hypothesis_id"):
            if item.get("status") in {"needs_missing_fact", "needs_reformulation"}:
                results.append(
                    {
                        "id": item.get("hypothesis_id"),
                        "question": item.get("claim"),
                        "cluster_id": cluster_id,
                    }
                )
        return sorted(results, key=lambda row: str(row.get("id")))

    async def get_attack_surface_map(self, cluster_id: str) -> dict[str, Any] | None:
        return await self._call_object("ontology.get_attack_surface_map", cluster_id=cluster_id)

    def _map_by_type(self, map_type: str, cluster_id: str) -> dict[str, Any] | None:
        for node in _latest_nodes(self._require_store()):
            if node.get("node_type") != map_type:
                continue
            props = _props(node)
            if cluster_id and props.get("cluster_id") not in {cluster_id, None, ""}:
                continue
            payload = props.get("payload")
            if isinstance(payload, str) and payload.startswith("{"):
                try:
                    parsed = json.loads(payload)
                    if isinstance(parsed, dict):
                        return parsed
                except json.JSONDecodeError:
                    pass
            return {"node_id": node.get("node_id"), "properties": props}
        return None

    def _ontology_get_attack_surface_map(self, params: dict[str, Any]) -> dict[str, Any] | None:
        return self._map_by_type("AttackSurfaceMap", str(params.get("cluster_id") or ""))

    async def get_value_at_risk_map(self, cluster_id: str) -> dict[str, Any] | None:
        return await self._call_object("ontology.get_value_at_risk_map", cluster_id=cluster_id)

    def _ontology_get_value_at_risk_map(self, params: dict[str, Any]) -> dict[str, Any] | None:
        return self._map_by_type("ValueAtRiskMap", str(params.get("cluster_id") or ""))

    async def get_spec_divergence_map(self, cluster_id: str) -> dict[str, Any] | None:
        return await self._call_object("ontology.get_spec_divergence_map", cluster_id=cluster_id)

    def _ontology_get_spec_divergence_map(self, params: dict[str, Any]) -> dict[str, Any] | None:
        return self._map_by_type("SpecDivergenceMap", str(params.get("cluster_id") or ""))

    async def get_integration_assumption_map(self, cluster_id: str) -> dict[str, Any] | None:
        return await self._call_object(
            "ontology.get_integration_assumption_map", cluster_id=cluster_id
        )

    def _ontology_get_integration_assumption_map(self, params: dict[str, Any]) -> dict[str, Any] | None:
        return self._map_by_type("IntegrationAssumptionMap", str(params.get("cluster_id") or ""))

    async def search_mechanisms(
        self, query_text: str, budget: int = 5
    ) -> list[dict[str, Any]]:
        return await self._call_list(
            "ontology.search_mechanisms", query_text=query_text, budget=budget
        )

    def _ontology_search_mechanisms(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        query = str(params.get("query_text") or "").lower()
        budget = int(params.get("budget") or 5)
        hits: list[dict[str, Any]] = []
        seen: set[str] = set()
        for node in _latest_nodes(self._require_store()):
            if node.get("node_type") not in {"MechanismCard", "ReasoningLens"}:
                continue
            props = _props(node)
            blob = " ".join(str(value) for value in props.values()).lower()
            if query and query not in blob and query not in str(node.get("node_id")):
                continue
            identifier = str(node.get("node_id"))
            if identifier in seen:
                continue
            seen.add(identifier)
            hits.append(_mechanism_card(node, props))
        hits.sort(key=lambda row: str(row.get("id")))
        return hits[: max(0, min(budget, 8))]

    async def search_incidents(
        self,
        protocol_type: str | None = None,
        mechanism: str | None = None,
        severity: str | None = None,
        limit: int = 3,
    ) -> list[dict[str, Any]]:
        return await self._call_list(
            "ontology.search_incidents",
            protocol_type=protocol_type,
            mechanism=mechanism,
            severity=severity,
            limit=limit,
        )

    def _ontology_search_incidents(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        limit = max(0, min(int(params.get("limit") or 3), 3))
        hits: list[dict[str, Any]] = []
        for node in _latest_nodes(self._require_store()):
            if node.get("node_type") != "IncidentCard":
                continue
            props = _props(node)
            if params.get("protocol_type") and props.get("protocol_type") != params["protocol_type"]:
                continue
            if params.get("mechanism") and props.get("mechanism") != params["mechanism"]:
                continue
            if params.get("severity") and props.get("severity") != params["severity"]:
                continue
            hits.append(
                {
                    "id": node.get("node_id"),
                    "title": props.get("title") or "incident",
                    "root_cause": props.get("root_cause"),
                    "mechanism": props.get("mechanism"),
                    "provenance": node.get("provenance") or [],
                    "historical_reference": True,
                }
            )
        hits.sort(key=lambda row: str(row.get("id")))
        return hits[:limit]

    async def search_vulnerability_patterns(
        self, attack_surface_tags: list[str]
    ) -> list[dict[str, Any]]:
        return await self._call_list(
            "ontology.search_vulnerability_patterns",
            attack_surface_tags=attack_surface_tags,
        )

    def _ontology_search_vulnerability_patterns(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        tags = {str(item).lower() for item in (params.get("attack_surface_tags") or [])}
        hits: list[dict[str, Any]] = []
        for node in _latest_nodes(self._require_store()):
            if node.get("node_type") != "VulnerabilityPattern":
                continue
            props = _props(node)
            blob = " ".join(str(value) for value in props.values()).lower()
            if tags and not any(tag in blob for tag in tags):
                continue
            hits.append(
                {
                    "id": node.get("node_id"),
                    "title": props.get("title") or "pattern",
                    "provenance": node.get("provenance") or [],
                    "historical_reference": True,
                }
            )
        return sorted(hits, key=lambda row: str(row.get("id")))

    async def get_tool_capabilities(
        self,
        attack_surface: str | None = None,
        protocol: str | None = None,
    ) -> list[dict[str, Any]]:
        return await self._call_list(
            "ontology.get_tool_capabilities",
            attack_surface=attack_surface,
            protocol=protocol,
        )

    def _ontology_get_tool_capabilities(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            from ayran.tools.registry import CapabilityRegistry

            registry = CapabilityRegistry(probe_on_load=False)
            manifests = [item.as_dict() for item in registry.list_capabilities()]
        except Exception:
            manifests = []
        attack_surface = str(params.get("attack_surface") or "").lower()
        protocol = str(params.get("protocol") or "").lower()
        if not attack_surface and not protocol:
            return manifests
        try:
            from ayran.knowledge.paths import default_knowledge_root
            from ayran.knowledge.taxonomy import load_taxonomy, tool_capabilities_for

            taxonomy = load_taxonomy(default_knowledge_root())
            allowed = {
                str(item.get("capability_id") or item.get("id") or "")
                for item in tool_capabilities_for(
                    taxonomy, attack_surface=attack_surface or None, protocol=protocol or None
                )
            }
        except Exception:
            return manifests
        if not allowed:
            return manifests
        filtered = []
        for item in manifests:
            identifier = str(item.get("capability_id") or item.get("id") or "")
            alias = str(item.get("alias") or item.get("name") or "").lower()
            if identifier in allowed or alias in {value.lower() for value in allowed}:
                filtered.append(item)
        return filtered or manifests

    async def get_promoted_lessons(self, tags: list[str] | None = None) -> list[dict[str, Any]]:
        _ = tags
        return await self._call_list("ontology.get_promoted_lessons", tags=tags)

    def _ontology_get_promoted_lessons(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        from ayran.learning.service import promoted_lessons

        tags = params.get("tags")
        tag_list = [str(item) for item in tags] if isinstance(tags, list) else None
        return promoted_lessons(self._require_store(), tags=tag_list)

    async def get_routing_policy(self) -> dict[str, Any]:
        result = await self._call_object("ontology.get_routing_policy")
        if result is None:
            raise TypeError("ontology.get_routing_policy expected an object")
        return result

    def _ontology_get_routing_policy(self, params: dict[str, Any]) -> dict[str, Any]:
        _ = params
        from ayran.learning.load import load_routing_policies
        from ayran.learning.release import baseline_routing_policy, load_routing_policy

        store = self._require_store()
        for policy in load_routing_policies(store):
            if policy.status == "active":
                return policy.model_dump(mode="json")
        try:
            from ayran.learning.paths import default_learning_root

            return load_routing_policy(default_learning_root()).model_dump(mode="json")
        except Exception:
            return baseline_routing_policy().model_dump(mode="json")

    def dispatch(self, method: str, params: dict[str, Any]) -> Any:
        handler = getattr(self, f"_{method.replace('.', '_')}", None)
        if handler is None:
            raise LookupError(method)
        return handler(params)


def snapshot_view(
    queries: OntologyQueries,
    *,
    cluster_id: str | None = None,
    run_id: str | None = None,
) -> GraphView:
    """Build a GraphView from a local GraphStore-backed query service."""

    store = queries.store
    if store is None:
        raise RuntimeError("snapshot_view requires a local GraphStore")
    cursor, event_hash, _ = store.projection.cursor()
    stream = store.stream
    identity = stream.get("target_identity") if isinstance(stream.get("target_identity"), dict) else {}
    cluster = cluster_id or DEFAULT_CLUSTER_ID
    hypotheses = _latest_domain(store, "hypotheses", "hypothesis_id")
    coverage = _latest_domain(store, "coverage_cells", "coverage_cell_id")
    evidence = _latest_domain(store, "evidence", "evidence_id")
    tool_runs = _latest_domain(store, "tool_runs", "tool_run_id")
    router_actions = _latest_domain(store, "router_actions", "router_action_id")
    nodes = _latest_nodes(store)
    edges = _latest_edges(store)
    maps: dict[str, dict[str, Any]] = {}
    dead_ends: list[dict[str, Any]] = []
    open_questions: list[dict[str, Any]] = []
    driver_states: dict[str, dict[str, Any]] = {}
    freeze_snapshots: dict[str, str] = {}
    payload_strikes: dict[str, int] = {}
    quarantined: list[str] = []
    budget_state: dict[str, Any] = {}
    source_units: list[dict[str, Any]] = []
    global_mechanisms: list[dict[str, Any]] = []
    global_incidents: list[dict[str, Any]] = []
    global_patterns: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []
    target_first: list[str] = []
    high_value = [cluster]
    no_progress = 0
    manual_next = False
    dual_review = False
    value_at_risk = 50
    for node in nodes:
        props = _props(node)
        node_type = str(node.get("node_type") or "")
        if node_type.endswith("Map") and isinstance(props.get("payload"), str):
            try:
                parsed = json.loads(str(props["payload"]))
                if isinstance(parsed, dict):
                    key = node_type.replace("Map", "")
                    key = {
                        "AttackSurface": "attack_surface",
                        "ControlFlow": "control_flow",
                        "DataFlow": "data_flow",
                        "ValueFlow": "value_flow",
                        "Authority": "authority",
                        "Temporal": "temporal",
                        "ValueAtRisk": "value_at_risk",
                        "SpecDivergence": "spec_divergence",
                        "IntegrationAssumption": "integration_assumption",
                    }.get(key, key.lower())
                    maps[key] = parsed
            except json.JSONDecodeError:
                pass
        elif node_type == "DeadEnd":
            dead_ends.append(
                {
                    "id": node.get("node_id"),
                    "approach": props.get("approach"),
                    "reason": props.get("reason"),
                }
            )
        elif node_type == "OpenQuestion":
            open_questions.append(
                {"id": node.get("node_id"), "question": props.get("question") or props.get("title")}
            )
        elif node_type == "DriverState":
            name = str(props.get("driver") or "")
            if name:
                driver_states[name] = {
                    "killed": bool(props.get("killed")),
                    "no_progress": int(props.get("no_progress") or 0),
                    "spend": int(props.get("spend") or 0),
                    "passes": int(props.get("passes") or 0),
                }
        elif node_type == "TargetFirstSnapshot":
            freeze_snapshots[str(props.get("cluster_id") or cluster)] = str(
                props.get("snapshot_hash") or ZERO_HASH
            )
            if props.get("completed"):
                target_first.append(str(props.get("cluster_id") or cluster))
        elif node_type == "PayloadStrike":
            source = str(props.get("source_id") or "")
            payload_strikes[source] = int(props.get("count") or 0)
        elif node_type == "Quarantine":
            quarantined.append(str(props.get("source_id") or node.get("node_id")))
        elif node_type == "RouterBudget":
            budget_state = {
                "remaining": int(props.get("remaining") or 100),
                "spent": int(props.get("spent") or 0),
                "tranche": int(props.get("tranche") or 100),
                "reserve_released": bool(props.get("reserve_released")),
            }
        elif node_type == "RouterControl":
            no_progress = int(props.get("no_progress_cycles") or 0)
            manual_next = bool(props.get("manual_next"))
            dual_review = bool(props.get("dual_review"))
        elif node_type in {"Function", "StateVariable", "Contract"}:
            source_units.append(
                {
                    "id": node.get("node_id"),
                    "kind": node_type.lower(),
                    "name": props.get("name") or props.get("canonical_key") or node.get("node_id"),
                    "locator": node.get("source_locator"),
                    "visibility": props.get("visibility"),
                }
            )
        elif node_type in {"MechanismCard", "ReasoningLens"}:
            global_mechanisms.append(
                {"id": node.get("node_id"), "title": props.get("title") or props.get("name")}
            )
        elif node_type == "IncidentCard":
            global_incidents.append({"id": node.get("node_id"), "title": props.get("title")})
        elif node_type == "VulnerabilityPattern":
            global_patterns.append({"id": node.get("node_id"), "title": props.get("title")})
        elif node_type == "Contradiction":
            contradictions.append(
                {
                    "id": node.get("node_id"),
                    "left": props.get("left"),
                    "right": props.get("right"),
                    "kind": props.get("kind"),
                }
            )
        elif node_type == "ValueAtRiskMap":
            try:
                value_at_risk = int(props.get("score") or 50)
            except (TypeError, ValueError):
                value_at_risk = 50
    view = GraphView(
        run_id=str(run_id or stream.get("run_id") or DEFAULT_RUN_ID),
        target_identity=dict(identity) if identity else {},
        cluster_id=cluster,
        cursor=int(cursor),
        event_hash=str(event_hash or ZERO_HASH),
        hypotheses=hypotheses,
        coverage_cells=coverage,
        evidence=evidence,
        tool_runs=tool_runs,
        dead_ends=dead_ends,
        open_questions=open_questions,
        nodes=nodes,
        edges=edges,
        maps=maps,
        contradictions=contradictions,
        source_units=source_units,
        global_mechanisms=global_mechanisms,
        global_incidents=global_incidents,
        global_patterns=global_patterns,
        router_actions=router_actions,
        driver_states=driver_states,
        budget_state=budget_state,
        freeze_snapshots=freeze_snapshots,
        payload_strikes=payload_strikes,
        quarantined_sources=quarantined,
        high_value_clusters=high_value or [cluster],
        target_first_completed=target_first,
        no_progress_cycles=no_progress,
        manual_next=manual_next,
        dual_review=dual_review,
        value_at_risk=value_at_risk,
        created_at="2026-08-12T12:00:00Z",
    )
    return view
