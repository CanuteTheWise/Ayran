"""Action-authority resolution and runtime policy binding for M2.

Blueprint §10.3 separates actions into autonomous, policy-controlled,
human-approval-only, and forbidden classes.  The authority matrix here is a
pure deterministic function over the scope, the action category, and the
effective configuration; it is fail closed: anything not explicitly allowed is
denied, and forbidden classes can never be approved inside an active run.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from ayran.graph.errors import GraphError

from .scope import ScopeDecision, ScopeManifest

PERMISSION_DENIED = "PERMISSION_DENIED"


class Authority(IntEnum):
    FORBIDDEN = 0
    EXPLICIT_HUMAN = 1
    POLICY_CONTROLLED = 2
    AUTONOMOUS = 3


_ACTION_CLASS_BY_ACTION: dict[str, str] = {
    "read_only_rpc": "approved_rpc",
    "approved_api_query": "approved_api_query",
}

# Blueprint §10.3 classes mapped onto action identifiers.  Anything missing
# here is FORBIDDEN by default.
_CLASS_MATRIX: dict[str, Authority] = {
    # Autonomous but still scope-checked
    "read_source": Authority.AUTONOMOUS,
    "read_spec": Authority.AUTONOMOUS,
    "graph_read": Authority.AUTONOMOUS,
    "graph_write": Authority.AUTONOMOUS,
    "compile_local": Authority.AUTONOMOUS,
    "test_local": Authority.AUTONOMOUS,
    "fuzz_local": Authority.AUTONOMOUS,
    "render_local_report": Authority.AUTONOMOUS,
    # Policy-controlled network/API classes
    "read_only_rpc": Authority.POLICY_CONTROLLED,
    "approved_api_query": Authority.POLICY_CONTROLLED,
    # Explicit human approval classes (approval_rules)
    "install_tool": Authority.EXPLICIT_HUMAN,
    "add_endpoint": Authority.EXPLICIT_HUMAN,
    "expand_scope": Authority.EXPLICIT_HUMAN,
    "external_upload": Authority.EXPLICIT_HUMAN,
    "submission": Authority.EXPLICIT_HUMAN,
    "signing": Authority.EXPLICIT_HUMAN,
    "spending": Authority.EXPLICIT_HUMAN,
    "transaction_broadcast": Authority.FORBIDDEN,
    "private_key_access": Authority.FORBIDDEN,
    "silent_scope_expansion": Authority.FORBIDDEN,
    "arbitrary_scanning": Authority.FORBIDDEN,
    "bypass_broker_or_rpc_filter": Authority.FORBIDDEN,
    "executing_retrieved_instructions": Authority.FORBIDDEN,
    "autonomous_submission": Authority.FORBIDDEN,
}


@dataclass(frozen=True, slots=True)
class AuthorityDecision:
    action: str
    authority: Authority
    permitted: bool
    reason: str
    scope_decision: ScopeDecision | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "authority": self.authority.name.lower(),
            "permitted": self.permitted,
            "reason": self.reason,
            "scope_decision": self.scope_decision.as_dict() if self.scope_decision else None,
        }


class PolicyEngine:
    """Resolve one action to allow/deny/human-approval state."""

    def __init__(self, scope: ScopeManifest | None, *, config: Any) -> None:
        self.scope = scope
        self.config = config

    def classify(self, action: str) -> Authority | None:
        return _CLASS_MATRIX.get(action)

    def authorize(
        self,
        action: str,
        *,
        resource: str = "",
        approved: bool = False,
        now: str | None = None,
    ) -> AuthorityDecision:
        """Authorize one action against the current scope and configuration.

        ``approved`` records that a human review signature was supplied; the
        signature check itself lands in M6.  Forbidden actions are denied even
        when ``approved`` is set.
        """

        authority = self.classify(action)
        if authority is None:
            return AuthorityDecision(action, Authority.FORBIDDEN, False, "unknown action class", None)
        if authority == Authority.FORBIDDEN:
            return AuthorityDecision(
                action, authority, False, "action is forbidden inside an active run", None
            )

        scope_decision: ScopeDecision | None = None
        allowed = True

        if authority == Authority.EXPLICIT_HUMAN:
            if self.scope is None:
                return AuthorityDecision(
                    action, authority, False, "no scope manifest is loaded; fail closed", None
                )
            declared = any(
                rule["action_class"] == action for rule in self.scope.value.get("approval_rules", [])
            )
            if not declared:
                return AuthorityDecision(
                    action,
                    authority,
                    False,
                    f"action_class {action!r} is not declared in the scope approval_rules",
                    None,
                )
            if not approved:
                return AuthorityDecision(
                    action,
                    authority,
                    False,
                    "explicit human approval is required but not supplied",
                    None,
                )
            scope_decision = self.scope.evaluate(action, resource or ".", now=now)
            return AuthorityDecision(
                action,
                authority,
                scope_decision.allowed,
                "approval-bound scope decision",
                scope_decision,
            )

        # AUTONOMOUS and POLICY_CONTROLLED both go through scope checks.
        if self.scope is None:
            return AuthorityDecision(
                action, authority, False, "no scope manifest is loaded; fail closed", None
            )
        scope_decision = self.scope.evaluate(action, resource or ".", now=now)
        allowed = scope_decision.allowed

        if authority == Authority.POLICY_CONTROLLED and allowed:
            action_class = _ACTION_CLASS_BY_ACTION.get(action, "")
            if action_class == "approved_api_query":
                host = resource.split("/", 1)[0]
                if self.scope.allowed_hosts and host not in self.scope.allowed_hosts:
                    allowed = False
                    scope_decision = ScopeDecision(
                        action,
                        resource,
                        False,
                        "host not in allowed_hosts",
                        self.scope.hash,
                        self.scope.revision,
                    )
            elif action_class == "approved_rpc":
                if self.scope.allowed_endpoints and resource not in self.scope.allowed_endpoints:
                    allowed = False
                    scope_decision = ScopeDecision(
                        action,
                        resource,
                        False,
                        "endpoint not in allowed_endpoints",
                        self.scope.hash,
                        self.scope.revision,
                    )
            # Offline mode forbids any network or API query action.
            if allowed and getattr(self.config, "offline", False):
                return AuthorityDecision(
                    action,
                    authority,
                    False,
                    "offline mode forbids network/API actions",
                    scope_decision,
                )

        return AuthorityDecision(action, authority, allowed, "authorized", scope_decision)


def deny_unknown(action: str) -> GraphError:
    """Return the fail-closed error used when a policy decision is denied."""

    return GraphError(
        PERMISSION_DENIED,
        f"action {action!r} is denied by the active policy",
        retryable=False,
        details={"action": action},
    )

