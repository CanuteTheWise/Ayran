"""Short-TTL, identity-bound, single-use credentials (spec §11.4).

Key GENERATION lives only in the Prime extension (TypeScript, outside
model-reachable Python): the sidecar constructs its
:class:`CredentialAuthority` from the key enrolled via the
``credentials.enroll`` RPC and then only VERIFIES and CONSUMES tokens against
it. Per-spawn challenger tokens are minted extension-side and vaulted
server-side via ``credentials.deliver``; the model never handles a challenger
token. Honest HMAC caveat: the key is symmetric, so post-enrollment the
sidecar COULD mint; mint-separation for challenger tokens is procedural (the
sidecar mints only the §11.4-sanctioned session-writer derivations), while
single-use / TTL / child-binding enforcement remains cryptographic and
server-side. ``verify(consume=True)`` enforces the exactly-one-submission
grant and is called at the verdict seal; the token is dead afterwards (reuse
is refused). ``revoke`` retires a token early.

Wire format (byte-compatible with ``prime/extension/credentials.ts``):
``body = base64url(JSON.stringify(payload with SORTED keys), unpadded)`` and
``signature = HMAC-SHA256 lowercase hex over body``; token = ``body + "." +
signature``. Payload fields are exactly ``jti`` (16 hex), ``iat``, ``exp``,
``grants`` (sorted), ``writer``, ``child_id``, ``session``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable, Mapping
from typing import Any

CREDENTIAL_GRANT_REMEMBER = "hypotheses.remember"
CREDENTIAL_GRANT_GATE_A = "gate_a_submission"
DEFAULT_TTL_SECONDS = 300.0

CLOCK = Callable[[], float]


class CredentialError(ValueError):
    """Stable refusal reason for a challenger/session credential."""

    def __init__(self, reason: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"code": f"CREDENTIAL_{self.reason}", "reason": self.reason}
        if self.details:
            value["details"] = self.details
        return value


def _b64encode(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _b64decode(body: str) -> bytes:
    padding = "=" * (-len(body) % 4)
    return base64.urlsafe_b64decode(body + padding)


class CredentialAuthority:
    """Short-TTL, identity-bound, single-use credentials (§11.4).

    Tokens are HMAC-SHA256 signed compact JSON. ``verify(consume=True)`` enforces
    the exactly-one-submission grant and is called at the verdict seal; the token
    is dead afterwards (reuse is refused). ``revoke`` retires a token early.
    """

    def __init__(
        self,
        key: bytes | None = None,
        *,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        clock: CLOCK | None = None,
    ) -> None:
        self._key = key or secrets.token_bytes(32)
        self.ttl_seconds = float(ttl_seconds)
        self._clock: CLOCK = clock or time.time
        self._used: set[str] = set()
        self._revoked: set[str] = set()

    def mint(
        self,
        *,
        grants: tuple[str, ...] | list[str],
        writer: Mapping[str, str] | None = None,
        child_id: str | None = None,
        session: str | None = None,
        ttl_seconds: float | None = None,
    ) -> str:
        now = self._clock()
        lifetime = self.ttl_seconds if ttl_seconds is None else float(ttl_seconds)
        payload = {
            "jti": secrets.token_hex(8),
            "iat": now,
            "exp": now + lifetime,
            "grants": sorted(str(grant) for grant in grants),
            "writer": dict(writer) if writer else None,
            "child_id": str(child_id) if child_id else None,
            "session": str(session) if session else None,
        }
        body = _b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        signature = hmac.new(self._key, body.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{body}.{signature}"

    def verify(
        self,
        token: str,
        *,
        grant: str | None = None,
        child_id: str | None = None,
        consume: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(token, str) or token.count(".") != 1:
            raise CredentialError("MALFORMED", details={"token_type": type(token).__name__})
        body, signature = token.split(".", 1)
        expected = hmac.new(self._key, body.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise CredentialError("SIGNATURE_INVALID")
        try:
            payload = json.loads(_b64decode(body))
        except (ValueError, UnicodeError) as error:
            raise CredentialError("MALFORMED", details={"parse": str(error)}) from error
        if not isinstance(payload, dict):
            raise CredentialError("MALFORMED")
        jti = str(payload.get("jti") or "")
        if not jti:
            raise CredentialError("MALFORMED")
        if jti in self._revoked:
            raise CredentialError("REVOKED", details={"jti": jti})
        if self._clock() >= float(payload.get("exp") or 0.0):
            raise CredentialError("EXPIRED", details={"jti": jti})
        if jti in self._used:
            # Single-use grant: reuse after the verdict seal is refused (§11.4).
            raise CredentialError("REVOKED", details={"jti": jti, "reuse": True})
        grants = {str(item) for item in (payload.get("grants") or [])}
        if grant is not None and grant not in grants:
            raise CredentialError("GRANT_MISMATCH", details={"required": grant, "grants": sorted(grants)})
        if child_id is not None and str(payload.get("child_id") or "") != child_id:
            raise CredentialError("BOUND_ID_MISMATCH", details={"required": child_id})
        if consume:
            self._used.add(jti)
        return payload

    def revoke(self, token: str) -> None:
        try:
            body = token.split(".", 1)[0]
            payload = json.loads(_b64decode(body))
            jti = str(payload.get("jti") or "")
        except (IndexError, ValueError, UnicodeError):
            return
        if jti:
            self._revoked.add(jti)

    def consume(self, token: str) -> None:
        """Retire the token's single grant — called at the verdict seal (§11.4)."""

        payload = self.verify(token)
        jti = str(payload.get("jti") or "")
        if jti:
            self._used.add(jti)

    def mint_session_writer(
        self,
        *,
        session: str,
        writer_kind: str,
        writer_id: str,
        ttl_seconds: float | None = None,
    ) -> str:
        return self.mint(
            grants=(CREDENTIAL_GRANT_REMEMBER,),
            writer={"kind": writer_kind, "id": writer_id},
            session=session,
            ttl_seconds=ttl_seconds,
        )

    def mint_challenger(
        self,
        *,
        child_id: str,
        ttl_seconds: float | None = None,
    ) -> str:
        return self.mint(
            grants=(CREDENTIAL_GRANT_GATE_A,),
            child_id=child_id,
            ttl_seconds=ttl_seconds,
        )

    def state(self) -> dict[str, Any]:
        return {
            "ttl_seconds": self.ttl_seconds,
            "used_credentials": len(self._used),
            "revoked_credentials": len(self._revoked),
        }
