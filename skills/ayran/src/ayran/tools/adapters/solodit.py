"""Solodit HTTP search adapter: privacy filter, pagination, rate limit, citation.

Speaks the captured Cyfrin contract: ``POST /api/v1/solodit/findings`` with an
``X-Cyfrin-API-Key`` header and a filters body. Protocol-name queries are
allowed and audited; contract addresses, transaction hashes, and raw URLs stay
hard-rejected.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ayran.graph.canonical import canonical_hash, utc_now
from ayran.tools.base import HttpAdapter, bytes_hash
from ayran.tools.errors import PARSER_FAILED, PRIVACY_REJECTED, ToolError
from ayran.tools.types import (
    ALIAS_SOLODIT,
    ZERO_HASH,
    ExecutionPolicy,
    RawRun,
    SoloditRecord,
    SoloditSearchRequest,
    SoloditSearchResult,
)

_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
_TX_RE = re.compile(r"0x[a-fA-F0-9]{64}")
_TARGETISH_RE = re.compile(
    r"\b(token|vault|pool|pair|router|proxy|implementation|usdc|usdt|weth|dai)\b",
    re.IGNORECASE,
)
_IDENTIFIER_RE = re.compile(r"\b[A-Z]{2,}[a-z]+[A-Z][A-Za-z]+\b")
PROVIDER_TERMS = "Solodit historical findings are leads only; provider terms apply at first use."
DEFAULT_CACHE_TTL_SECONDS = 86400
_KEY_FILE = Path.home() / ".config" / "ayran" / "solodit.key"


def hard_privacy_issues(query: str) -> list[str]:
    """Categories that always refuse a query: real identifiers, never names."""

    issues: list[str] = []
    if _ADDRESS_RE.search(query):
        issues.append("contract-address")
    if _TX_RE.search(query):
        issues.append("transaction-hash")
    if re.search(r"https?://", query, re.IGNORECASE):
        issues.append("absolute-url")
    return issues


def soft_privacy_flags(query: str) -> list[str]:
    """Audited-but-allowed patterns: public protocol/project style names."""

    flags: list[str] = []
    if _IDENTIFIER_RE.search(query) and _TARGETISH_RE.search(query):
        flags.append("target-specific-identifier")
    return flags


def privacy_issues(query: str) -> list[str]:
    """Backward-compatible view: only the hard-rejected categories."""

    return hard_privacy_issues(query)


def query_hash(request: SoloditSearchRequest) -> str:
    return canonical_hash(
        {
            "query": request.query.strip().lower(),
            "page": request.page,
            "page_size": request.page_size,
            "cursor": request.cursor,
            "category": request.category,
            "severity": request.severity,
        }
    )


class SoloditAdapter(HttpAdapter):
    alias = ALIAS_SOLODIT
    request_type = SoloditSearchRequest
    cache: dict[str, tuple[float, SoloditSearchResult, bytes]]

    def __init__(self, manifest: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(manifest, **kwargs)
        self.cache = {}
        self.privacy_audit: list[dict[str, str]] = []
        self.provider_terms_recorded = False
        self.cache_ttl_seconds = DEFAULT_CACHE_TTL_SECONDS

    def _audit(self, query_digest: str, rejected: bool, reason: str) -> None:
        self.privacy_audit.append(
            {
                "query_hash": query_digest,
                "rejected": "true" if rejected else "false",
                "reason": reason,
                "at": utc_now(),
            }
        )

    def allowed_host(self, policy: ExecutionPolicy, url: str) -> bool:
        host = urlparse(url).hostname or ""
        if policy.offline:
            return False
        if policy.network not in {"approved-api", "approved-source-fetch"}:
            return False
        return not policy.allowed_hosts or host in policy.allowed_hosts

    @staticmethod
    def _api_key() -> str:
        """Cyfrin API key: ``AYRAN_SOLODIT_API_KEY`` env override, then the
        operator key file (``~/.config/ayran/solodit.key``). Attached as a
        request header only; never logged, hashed into receipts, or echoed."""

        value = os.environ.get("AYRAN_SOLODIT_API_KEY", "").strip()
        if value:
            return value
        try:
            return _KEY_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    async def run(self, request: SoloditSearchRequest, policy: ExecutionPolicy) -> RawRun:  # type: ignore[override]
        started = utc_now()
        digest = query_hash(request)
        issues = hard_privacy_issues(request.query)
        if issues:
            self._audit(digest, True, ",".join(issues))
            raise ToolError(
                PRIVACY_REJECTED,
                "Solodit queries must be abstract/mechanism-based; addresses, hashes, and raw URLs are forbidden",
                details={"reasons": issues, "query_hash": digest},
            )
        soft = soft_privacy_flags(request.query)
        audit_reason = "mechanism-query"
        if request.protocol:
            audit_reason = "protocol-name-query"
        elif soft:
            audit_reason = f"mechanism-query;{','.join(soft)}"
        self._audit(digest, False, audit_reason)
        cached = self.cache.get(digest)
        now = time.monotonic()
        if cached and cached[0] > now:
            result, body = cached[1], cached[2]
            ended = utc_now()
            return RawRun(
                argv=["solodit", "search", digest],
                cwd=None,
                env_fingerprint=ZERO_HASH,
                started_at=started,
                ended_at=ended,
                exit_code=0,
                signal=None,
                stdout=body,
                stderr=b"",
                stdout_truncated=False,
                stderr_truncated=False,
                stdout_hash=bytes_hash(body),
                stderr_hash=bytes_hash(b""),
                output_file_hashes={},
                input_hashes=[digest],
                executable_hash=None,
                timeout=False,
                failure_type=None,
                extra={"parsed": result.model_dump(), "cache_hit": True},
                privacy_audit=list(self.privacy_audit),
                http_status=200,
            )
        endpoint = self.endpoint(self.environment)
        if not self.allowed_host(policy, endpoint):
            raise ToolError(
                "policy",
                "Solodit endpoint is not permitted by the current execution policy",
                details={"endpoint_hash": bytes_hash(endpoint.encode("utf-8"))},
            )
        filters: dict[str, Any] = {}
        keywords = request.query.strip()
        if keywords:
            # Live API (verified 2026-08-24): keywords is a single string,
            # not the array an older capture suggested.
            filters["keywords"] = keywords
        if request.protocol:
            filters["protocol"] = request.protocol
        if request.severity:
            filters["impact"] = [request.severity.upper()]
        if request.category:
            filters["tags"] = [{"value": request.category}]
        payload_body: dict[str, Any] = {
            "page": request.page,
            "pageSize": request.page_size,
            "sortField": "Recency",
            "sortDirection": "DESC",
        }
        if filters:
            payload_body["filters"] = filters
        url = f"{endpoint}/api/v1/solodit/findings"
        timeout = min(policy.timeout_seconds, int(self.manifest.get("timeout_seconds") or 30))
        api_key = self._api_key()
        headers = {"X-Cyfrin-API-Key": api_key} if api_key else None
        try:
            self._rate_limit()
            response = self.http_post_json(url, payload_body, timeout=timeout, headers=headers)
        except ToolError as error:
            ended = utc_now()
            failure = "timeout" if "timed" in error.message.lower() else "network"
            return RawRun(
                argv=["solodit", "search", digest],
                cwd=None,
                env_fingerprint=ZERO_HASH,
                started_at=started,
                ended_at=ended,
                exit_code=None,
                signal=None,
                stdout=b"",
                stderr=error.message.encode("utf-8"),
                stdout_truncated=False,
                stderr_truncated=False,
                stdout_hash=bytes_hash(b""),
                stderr_hash=bytes_hash(error.message.encode("utf-8")),
                output_file_hashes={},
                input_hashes=[digest],
                executable_hash=None,
                timeout=failure == "timeout",
                failure_type=failure,  # type: ignore[arg-type]
                privacy_audit=list(self.privacy_audit),
            )
        ended = utc_now()
        if not self.provider_terms_recorded:
            self.provider_terms_recorded = True
        raw = RawRun(
            argv=["solodit", "search", digest],
            cwd=None,
            env_fingerprint=ZERO_HASH,
            started_at=started,
            ended_at=ended,
            exit_code=0 if response.status < 400 else response.status,
            signal=None,
            stdout=response.body,
            stderr=b"",
            stdout_truncated=len(response.body) >= self.max_response_bytes,
            stderr_truncated=False,
            stdout_hash=bytes_hash(response.body),
            stderr_hash=bytes_hash(b""),
            output_file_hashes={},
            input_hashes=[digest],
            executable_hash=None,
            timeout=False,
            failure_type=None if response.status < 400 else "network",
            extra={"query_hash": digest, "provider_terms": PROVIDER_TERMS},
            privacy_audit=list(self.privacy_audit),
            http_status=response.status,
        )
        if response.status == 429:
            raw.failure_type = "network"
            raw.extra["rate_limited"] = True
        return raw

    def parse(self, raw: RawRun) -> SoloditSearchResult:
        if raw.extra.get("parsed"):
            parsed = SoloditSearchResult.model_validate(raw.extra["parsed"])
            parsed.cache_hit = True
            return parsed
        if not raw.stdout:
            raise ToolError(PARSER_FAILED, "Solodit produced an empty body; HTTP status is not a finding")
        try:
            payload = json.loads(raw.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ToolError(PARSER_FAILED, f"Solodit JSON parse failed: {error}") from error
        if not isinstance(payload, dict):
            raise ToolError(PARSER_FAILED, "Solodit response must be an object")
        findings = payload.get("findings")
        if not isinstance(findings, list):
            raise ToolError(PARSER_FAILED, "Solodit response must carry a findings list")
        retrieved = utc_now()
        records: list[SoloditRecord] = []
        for item in findings:
            if not isinstance(item, dict):
                continue
            record_id = str(item.get("id") or "")
            slug = str(item.get("slug") or "")
            source_url = str(
                item.get("source_link")
                or item.get("github_link")
                or (f"/issues/{slug}" if slug else "")
            )
            if not record_id or not source_url:
                raise ToolError(
                    PARSER_FAILED,
                    "every Solodit finding must include an id and a resolvable link",
                )
            records.append(
                SoloditRecord(
                    title=str(item.get("title") or "untitled")[:256],
                    severity=(str(item["impact"]).upper()[:64] if item.get("impact") else None),
                    category=(str(item["firm_name"])[:128] if item.get("firm_name") else None),
                    protocol=(str(item["protocol_name"])[:128] if item.get("protocol_name") else None),
                    source_url=source_url[:2048],
                    record_id=record_id[:128],
                    retrieved_at=retrieved,
                )
            )
        digest = str(raw.extra.get("query_hash") or bytes_hash(raw.stdout))
        metadata = payload.get("metadata") or {}
        try:
            page = int(metadata.get("currentPage") or payload.get("page") or 1)
            total_pages = int(metadata.get("totalPages") or 1)
        except (TypeError, ValueError):
            page, total_pages = 1, 1
        next_cursor = str(page + 1) if page < total_pages else None
        result = SoloditSearchResult(
            query_hash=digest,
            records=records,
            page=page,
            next_cursor=next_cursor,
            provider_terms=PROVIDER_TERMS,
            cache_hit=False,
        )
        self.cache[digest] = (time.monotonic() + self.cache_ttl_seconds, result, raw.stdout)
        return result
