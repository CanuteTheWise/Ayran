"""Cumulative A0-A7 capability sets from blueprint section 20.1."""

from __future__ import annotations

from ayran.evaluation.models import ArmId, ArmSpec

KNOWLEDGE_SEED = "ayran-global-seed-v1"
KNOWLEDGE_EXPANDED = "ayran-global-expanded-v1"
LEARNING_BASELINE = "ayran-routing-baseline-v1"

ARM_SEQUENCE: tuple[ArmId, ...] = ("A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7")

_ARMS: dict[ArmId, ArmSpec] = {
    "A0": ArmSpec(
        arm="A0",
        capabilities=["prime.stock"],
        attribution="what can the substrate and configured model achieve alone?",
    ),
    "A1": ArmSpec(
        arm="A1",
        capabilities=["prime.stock", "scope.policy", "graph.target", "context.compiler", "router"],
        attribution="does durable target/evidence state improve coverage, continuity, safety, and proof discipline?",
    ),
    "A2": ArmSpec(
        arm="A2",
        capabilities=[
            "prime.stock",
            "scope.policy",
            "graph.target",
            "context.compiler",
            "router",
            "adapter.slither",
            "adapter.foundry",
        ],
        attribution="what deterministic mapping and executable-validation lift do the initial tools add?",
    ),
    "A3": ArmSpec(
        arm="A3",
        capabilities=[
            "prime.stock",
            "scope.policy",
            "graph.target",
            "context.compiler",
            "router",
            "adapter.slither",
            "adapter.foundry",
            "specialists.routed",
        ],
        attribution="do bounded domain views improve unique validated yield rather than duplicate activity?",
    ),
    "A4": ArmSpec(
        arm="A4",
        capabilities=[
            "prime.stock",
            "scope.policy",
            "graph.target",
            "context.compiler",
            "router",
            "adapter.slither",
            "adapter.foundry",
            "specialists.routed",
            "graph.global.seed",
        ],
        attribution="does curated methodology/precedent add recall without crowding out novelty?",
        knowledge_release=KNOWLEDGE_SEED,
    ),
    "A5": ArmSpec(
        arm="A5",
        capabilities=[
            "prime.stock",
            "scope.policy",
            "graph.target",
            "context.compiler",
            "router",
            "adapter.slither",
            "adapter.foundry",
            "specialists.routed",
            "graph.global.seed",
            "gate.a",
            "gate.b",
        ],
        attribution="how do precision, defect-pinning, and false-PoC rejection change?",
        knowledge_release=KNOWLEDGE_SEED,
    ),
    "A6": ArmSpec(
        arm="A6",
        capabilities=[
            "prime.stock",
            "scope.policy",
            "graph.target",
            "context.compiler",
            "router",
            "adapter.slither",
            "adapter.foundry",
            "specialists.routed",
            "graph.global.seed",
            "gate.a",
            "gate.b",
            "adapter.fizz",
        ],
        attribution="what incremental stateful property and sequence coverage is gained?",
        knowledge_release=KNOWLEDGE_SEED,
        experimental=True,
    ),
    "A7": ArmSpec(
        arm="A7",
        capabilities=[
            "prime.stock",
            "scope.policy",
            "graph.target",
            "context.compiler",
            "router",
            "adapter.slither",
            "adapter.foundry",
            "specialists.routed",
            "graph.global.expanded",
            "gate.a",
            "gate.b",
            "adapter.fizz",
        ],
        attribution="does the expanded corpus/tool portfolio generalize across families at acceptable cost and anchoring risk?",
        knowledge_release=KNOWLEDGE_EXPANDED,
        learning_policy=LEARNING_BASELINE,
        experimental=True,
    ),
}


def arm_spec(arm: ArmId) -> ArmSpec:
    return _ARMS[arm]


def has_capability(arm: ArmId, capability: str) -> bool:
    return capability in _ARMS[arm].capabilities


def order_for_seed(seed: int) -> tuple[ArmId, ...]:
    """Alternate cumulative arm order across the three fixed seeds."""

    if seed == 13:
        return tuple(reversed(ARM_SEQUENCE))
    if seed == 21:
        evens = ARM_SEQUENCE[0::2]
        odds = ARM_SEQUENCE[1::2]
        return evens + odds
    return ARM_SEQUENCE
