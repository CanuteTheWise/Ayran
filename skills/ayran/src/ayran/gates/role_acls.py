"""Per-role verb ACLs for specialist/challenger rlm() grants (spec §5.5, §5.7, §11.1).

Specialists hold ZERO sidecar-write verbs: outputs return over the spawning
root's channel. The Gate A challenger keeps exactly one grant —
``gate_a_submission`` — minted by CredentialAuthority.mint_challenger.
"""

from __future__ import annotations

from ayran.context.lenses import SPECIALIST_ROLES

WRITE_VERBS = frozenset(
    {
        "hypotheses.remember",
        "attach_evidence",
        "evidence.gate_b",
        "map_target",
        "finding.build",
        "report.render",
    }
)

# Empty grant tuples: verify(grant=W) raises GRANT_MISMATCH for every write verb.
ROLE_GRANTS: dict[str, tuple[str, ...]] = {role: () for role in SPECIALIST_ROLES}
