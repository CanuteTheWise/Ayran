"""Sanctioned post-mortem enrichment for DeFiHackLabs incident cards.

Operator-sanctioned (2026-08-24): follow the public write-up links that
incident headers carry, extract readable text, screen it through the same
injection/credential safety scans as every other corpus byte, derive a
mechanism label when the text states one, and retain the fetched text under
``raw/defihacklabs/postmortems/`` with URL + timestamp provenance.

Every failure mode is a disclosed status - never fabricated content:
``ok``, ``paywall`` (public teaser kept, flagged), ``x-wall`` (platform
shell returned), ``http-<code>``, ``network``, ``unsupported-content``,
``too-large``, ``blocked-safety``.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from ayran.graph.canonical import canonical_line
from ayran.knowledge.defihacklabs import (
    DEFIHACKLABS_ORIGIN,
    _header_comment_lines,
    _mechanism_keyword,
    _strip_comment_marks,
)
from ayran.knowledge.paths import raw_dir
from ayran.knowledge.safety import scan_text

MAX_FETCH_BYTES = 1_000_000
DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_DELAY_SECONDS = 0.4
EXCERPT_CHARS = 2400
USER_AGENT = "ayran-postmortem-enricher/1.0 (local audit research)"
_PAYWALL_MARKERS = (
    "subscribe to continue",
    "create an account to read",
    "sign in to continue",
    "start your free trial",
    "already a subscriber",
)
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_BLOCK_TAGS = {"script", "style", "nav", "footer", "button", "svg", "form", "noscript"}
_TEXT_TAGS = {"p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "pre", "blockquote", "td"}


def extract_header_links(source_text: str) -> list[str]:
    """Ordered unique external links from the card-header comments.

    Self-references (the pinned GitHub blob URLs Ayran itself stamps into
    provenance) are excluded; every real external write-up link stays.
    """

    links: list[str] = []
    seen: set[str] = set()
    for line in _header_comment_lines(source_text):
        clean = _strip_comment_marks(line)
        for match in _URL_RE.finditer(clean):
            url = match.group(0).rstrip(".,;:)'\"")
            key = url.lower()
            if key in seen:
                continue
            if url.startswith(DEFIHACKLABS_ORIGIN):
                continue
            seen.add(key)
            links.append(url)
    return links


class _ReadableText(HTMLParser):
    """Stdlib-only HTML-to-text extraction bounded to readable blocks."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip_depth = 0
        self._open_text_tag = False

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        lowered = tag.lower()
        if lowered in _BLOCK_TAGS:
            self._skip_depth += 1
            return
        if lowered == "br":
            self._chunks.append("\n")
            return
        if lowered in _TEXT_TAGS:
            if self._chunks and self._chunks[-1] != "\n":
                self._chunks.append("\n")
            self._open_text_tag = True

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in _BLOCK_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
            return
        if lowered in _TEXT_TAGS:
            self._chunks.append("\n")
            self._open_text_tag = False

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0 and data.strip():
            self._chunks.append(data)

    def text(self) -> str:
        raw = "".join(self._chunks)
        return re.sub(r"\n{3,}", "\n\n", raw).strip()


def html_to_text(body: str) -> str:
    extractor = _ReadableText()
    try:
        extractor.feed(body)
        extractor.close()
    except Exception:
        return ""
    return extractor.text()


def _looks_like_shell(text: str) -> bool:
    """Platform shells (X/Twitter walls) return tiny script-only pages."""

    lowered = text[:2000].lower()
    return len(text) < 200 and ("javascript" in lowered or "sign up" in lowered or "log in" in lowered)


def fetch(url: str, *, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Fetch one write-up page. Never raises; always returns a status dict."""

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,text/plain,*/*"})
    try:
        with _open(request, timeout=timeout) as response:
            payload = response.read(MAX_FETCH_BYTES + 1)
    except urllib.error.HTTPError as error:
        return {"url": url, "status": f"http-{error.code}", "text": None}
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return {"url": url, "status": "network", "text": None, "reason": str(error)[:160]}
    if len(payload) > MAX_FETCH_BYTES:
        return {"url": url, "status": "too-large", "text": None}
    text = payload.decode("utf-8", errors="replace")
    head = text[:4000].lower()
    if "<html" in head or "<!doctype" in head or "<p" in head or "<div" in head:
        text = html_to_text(text)
    host = ""
    match = re.match(r"https?://([^/]+)", url, re.IGNORECASE)
    if match:
        host = match.group(1).lower()
    if any(marker in head for marker in _PAYWALL_MARKERS):
        return {"url": url, "status": "paywall", "text": text[:EXCERPT_CHARS] if text else None}
    if not text or not text.strip():
        return {"url": url, "status": "empty", "text": None}
    if host in {"x.com", "twitter.com"} or (_looks_like_shell(text) and "x.com" in host):
        return {"url": url, "status": "x-wall", "text": text[:EXCERPT_CHARS]}
    safety = scan_text(text[: MAX_FETCH_BYTES])
    if not safety.accepted:
        return {"url": url, "status": "blocked-safety", "text": None}
    return {"url": url, "status": "ok", "text": text[:EXCERPT_CHARS]}


# Test seam: tests monkeypatch this callable instead of the network.
_open = urllib.request.urlopen


def _record_links(raw_path: Path) -> tuple[list[str], str]:
    source_text = raw_path.read_bytes()[:1_048_576].decode("utf-8", errors="replace")
    return extract_header_links(source_text), source_text


def enrich(
    knowledge_root: Path,
    *,
    limit: int | None = None,
    delay: float = DEFAULT_DELAY_SECONDS,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    dry_run: bool = False,
    refresh: bool = False,
) -> dict[str, Any]:
    """Enrich staged DeFiHackLabs cards from their linked write-ups."""

    staging_file = knowledge_root / "staging" / "defihacklabs" / "records.json"
    if not staging_file.is_file():
        raise FileNotFoundError(f"no staged DeFiHackLabs records at {staging_file}")
    envelope = json.loads(staging_file.read_text(encoding="utf-8"))
    records = envelope.get("records") if isinstance(envelope, dict) else envelope
    if isinstance(records, dict):
        records = list(records.values())
    records = list(records or [])

    postmortem_dir = raw_dir(knowledge_root, "defihacklabs") / "postmortems"
    summary: dict[str, Any] = {
        "cards": len(records),
        "with_links": 0,
        "planned_fetches": 0,
        "actual_fetches": 0,
        "fetched_ok": 0,
        "paywall": 0,
        "x_wall": 0,
        "network_fail": 0,
        "skipped_safety": 0,
        "other_fail": 0,
        "enriched_records": 0,
        "mechanisms_after": {},
        "dry_run": bool(dry_run),
    }
    mechanisms: dict[str, int] = {}
    pending: list[tuple[dict[str, Any], str, list[str]]] = []

    for record in records:
        locator = str((record.get("source_ref") or {}).get("locator") or "")
        raw_path = knowledge_root / "raw" / "defihacklabs" / locator
        if not raw_path.is_file():
            continue
        links, _source_text = _record_links(raw_path)
        if not links:
            continue
        summary["with_links"] += 1
        existing = record.get("postmortem") or {}
        if existing.get("status") == "ok" and not refresh:
            summary["fetched_ok"] += 1
            continue
        pending.append((record, locator, links))

    planned = sum(len(links) for _, _, links in pending)
    if limit is not None:
        capped: list[tuple[dict[str, Any], str, list[str]]] = []
        budget = int(limit)
        for _record, _locator, links in pending:
            take = links[:budget]
            if take:
                capped.append((_record, _locator, take))
                budget -= len(take)
            if budget <= 0:
                break
        planned = sum(len(links) for _, _, links in capped)
        pending = capped
    summary["planned_fetches"] = planned

    if dry_run:
        hosts: dict[str, int] = {}
        for _record, _locator, links in pending:
            for url in links:
                host = re.match(r"https?://([^/]+)", url, re.IGNORECASE)
                hosts[(host.group(1).lower() if host else "unknown")] = hosts.get(host.group(1).lower() if host else "unknown", 0) + 1
        summary["hosts"] = dict(sorted(hosts.items(), key=lambda kv: -kv[1]))
        return summary

    fetched_cache: dict[str, dict[str, Any]] = {}
    for record, _locator, links in pending:
        for url in links:
            # First usable write-up wins for this card; later links are
            # redundant once readable analysis text is already attached.
            existing_block = record.get("postmortem") or {}
            if existing_block.get("status") in {"ok", "paywall"} and existing_block.get("sha256"):
                break
            outcome = fetched_cache.get(url)
            if outcome is None:
                outcome = fetch(url, timeout=timeout)
                fetched_cache[url] = outcome
                summary["actual_fetches"] += 1
                if delay > 0:
                    time.sleep(delay)
            status = outcome["status"]
            if status == "ok":
                summary["fetched_ok"] += 1
            elif status == "paywall":
                summary["paywall"] += 1
            elif status == "x-wall":
                summary["x_wall"] += 1
            elif status.startswith("http-") or status in {"network", "empty"}:
                summary["network_fail"] += 1
            elif status == "blocked-safety":
                summary["skipped_safety"] += 1
            else:
                summary["other_fail"] += 1
            if status not in {"ok", "paywall"} or not outcome.get("text"):
                record["postmortem"] = {"url": url, "status": status}
                continue
            text = str(outcome["text"])
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if not dry_run:
                postmortem_dir.mkdir(parents=True, exist_ok=True)
                target = postmortem_dir / f"{digest[:16]}.txt"
                if not target.exists():
                    stamped = f"# url: {url}\n# fetched_at: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n\n{text}\n"
                    target.write_text(stamped, encoding="utf-8")
            mechanism = _mechanism_keyword([text[:6000]])
            if mechanism:
                mechanisms[mechanism] = mechanisms.get(mechanism, 0) + 1
                record["mechanism"] = mechanism
            record["postmortem"] = {
                "url": url,
                "status": status,
                "chars": len(text),
                "sha256": f"sha256:{digest}",
                "path": f"postmortems/{digest[:16]}.txt",
                "excerpt": text[:400],
            }
            summary["enriched_records"] += 1

    for keyword, count in mechanisms.items():
        summary["mechanisms_after"][keyword] = count
    if not dry_run:
        staging_file.parent.mkdir(parents=True, exist_ok=True)
        staging_file.write_bytes(canonical_line(envelope))
    return summary
