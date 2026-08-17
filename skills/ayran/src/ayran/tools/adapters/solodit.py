"""Solodit HTTP search adapter: privacy filter, pagination, rate limit, citation."""

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import urlencode, urlparse

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
PROVIDER_TERMS = "Solodit historical findings are leads only; provider terms apply at first use."
DEFAULT_CACHE_TTL_SECONDS = 86400


def privacy_issues(query: str) -> list[str]:
    issues: list[str] = []
    if _ADDRESS_RE.search(query):
        issues.append("contract-address")
    if _TX_RE.search(query):
        issues.append("transaction-hash")
    if re.search(r"\b[A-Z]{2,}[a-z]+[A-Z][A-Za-z]+\b", query) and _TARGETISH_RE.search(query):
        issues.append("target-specific-identifier")
    if re.search(r"https?://", query, re.IGNORECASE):
        issues.append("absolute-url")
    return issues


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

    async def run(self, request: SoloditSearchRequest, policy: ExecutionPolicy) -> RawRun:  # type: ignore[override]
        started = utc_now()
        digest = query_hash(request)
        issues = privacy_issues(request.query)
        if issues:
            self._audit(digest, True, ",".join(issues))
            raise ToolError(
                PRIVACY_REJECTED,
                "Solodit queries must be abstract/mechanism-based; target identifiers are forbidden",
                details={"reasons": issues, "query_hash": digest},
            )
        self._audit(digest, False, "mechanism-query")
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
        params = {
            "q": request.query,
            "page": str(request.page),
            "page_size": str(request.page_size),
        }
        if request.cursor:
            params["cursor"] = request.cursor
        if request.category:
            params["category"] = request.category
        if request.severity:
            params["severity"] = request.severity
        url = f"{endpoint}/search?{urlencode(params)}"
        timeout = min(policy.timeout_seconds, int(self.manifest.get("timeout_seconds") or 30))
        try:
            self._rate_limit()
            response = self.http_get(url, timeout=timeout)
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
        results = payload.get("results") or payload.get("items") or payload.get("data") or []
        if not isinstance(results, list):
            raise ToolError(PARSER_FAILED, "Solodit results must be a list")
        retrieved = utc_now()
        records: list[SoloditRecord] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            source_url = str(item.get("source_url") or item.get("url") or "")
            record_id = str(item.get("record_id") or item.get("id") or "")
            if not source_url or not record_id:
                raise ToolError(PARSER_FAILED, "every Solodit record must include source_url and record_id")
            records.append(
                SoloditRecord(
                    title=str(item.get("title") or "untitled")[:256],
                    severity=str(item["severity"]) if item.get("severity") else None,
                    category=str(item["category"]) if item.get("category") else None,
                    protocol=str(item["protocol"]) if item.get("protocol") else None,
                    source_url=source_url[:2048],
                    record_id=record_id[:128],
                    retrieved_at=retrieved,
                )
            )
        digest = str(raw.extra.get("query_hash") or bytes_hash(raw.stdout))
        page = 1
        next_cursor = payload.get("next_cursor") or payload.get("next")
        result = SoloditSearchResult(
            query_hash=digest,
            records=records,
            page=int(payload.get("page") or page),
            next_cursor=str(next_cursor) if next_cursor else None,
            provider_terms=PROVIDER_TERMS,
            cache_hit=False,
        )
        self.cache[digest] = (time.monotonic() + self.cache_ttl_seconds, result, raw.stdout)
        return result
