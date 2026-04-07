from __future__ import annotations

import html
import re
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qs, urlparse

from app.clients import http_client
from app.logging_utils import get_logger, log_event
from app.models import SearchRequest, SearchResult

logger = get_logger("search")

HTML_TAG_RE = re.compile(r"<[^>]+>")
SCRIPT_STYLE_RE = re.compile(r"<(script|style|noscript|svg|iframe).*?</\1>", re.I | re.S)
BLOCK_RE = re.compile(r"<(article|main|section|div|p)[^>]*>(.*?)</\1>", re.I | re.S)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
META_DESC_RE = re.compile(
    r'<meta[^>]+(?:name|property)=["\'](?:description|og:description)["\'][^>]+content=["\'](.*?)["\']',
    re.I | re.S,
)
META_DATE_RE = re.compile(
    r'<meta[^>]+(?:name|property|itemprop)=["\'](?:article:published_time|og:published_time'
    r'|publication_date|pubdate|datePublished)["\'][^>]+content=["\'](.*?)["\']',
    re.I | re.S,
)
CANONICAL_RE = re.compile(
    r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\'](.*?)["\']', re.I | re.S
)
RESULT_RE = re.compile(
    r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="(?P<href>[^"]+)"[^>]*>(?P<title>.*?)</a>',
    re.I | re.S,
)
SNIPPET_RE = re.compile(
    r'<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>', re.I | re.S
)
WHITESPACE_RE = re.compile(r"\s+")
_YEAR_RE = re.compile(r"\b(20\d{2})\b")
_LAST_N_RE = re.compile(r"last\s+(\d+)\s+(year|month|week|day)s?", re.I)

STOPWORDS = {
    "a", "an", "and", "attacks", "breach", "data", "for", "in", "last",
    "of", "on", "or", "sector", "the", "to", "with", "years",
}
NOISE_DOMAINS = {
    "accounts.google.com", "google.com", "myaccount.google.com",
    "news.google.com", "news.url.google.com", "support.google.com",
    "www.google.com", "www.gstatic.com",
}
CYBER_KEYWORDS = {
    "breach", "cve", "exploit", "exploitation", "malware",
    "ransomware", "threat", "vulnerability", "zero-day",
}
TRUSTED_DOMAIN_HINTS = (
    "security", "threat", "advisory", "blog", "news",
    "cisa.gov", "nist.gov", "unit42", "crowdstrike", "thehackernews",
)

_HYDRATION_WORKERS = 4

# URL paths that indicate tag indexes, search pages, or archive listings
# rather than actual incident articles or advisories.
_LOW_SIGNAL_PATH_HINTS = (
    "/search/", "/label/", "/tag/", "/category/", "/anthology/",
    "/archive/", "/topics/", "/latest/",
)


# ── time window ──────────────────────────────────────────────────────

@dataclass
class TimeWindow:
    """Half-open interval ``[start, end)``."""

    start: datetime | None
    end: datetime | None


def _normalize_utc(dt: datetime) -> datetime:
    """Ensure *dt* is timezone-aware in UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def parse_time_window(time_range: str | None) -> TimeWindow | None:
    """Convert a free-text time range into a ``TimeWindow``.

    Supported patterns:
    - ``"last 2 years"`` / ``"last 6 months"`` / ``"last 30 days"``
    - ``"2023"`` → ``[2023-01-01, 2024-01-01)``
    """
    if not time_range:
        return None
    match = _LAST_N_RE.search(time_range)
    if match:
        n = int(match.group(1))
        unit = match.group(2).lower()
        delta = {
            "year": timedelta(days=365 * n),
            "month": timedelta(days=30 * n),
            "week": timedelta(weeks=n),
            "day": timedelta(days=n),
        }
        return TimeWindow(
            start=datetime.now(UTC) - delta.get(unit, timedelta(days=365 * n)),
            end=None,
        )
    year_match = _YEAR_RE.search(time_range)
    if year_match:
        year = int(year_match.group(1))
        return TimeWindow(
            start=datetime(year, 1, 1, tzinfo=UTC),
            end=datetime(year + 1, 1, 1, tzinfo=UTC),
        )
    return None


def in_window(dt: datetime | None, window: TimeWindow | None) -> bool:
    """Return ``True`` if *dt* falls inside *window*.

    Missing *dt* or *window* is treated as "no constraint".
    """
    if dt is None or window is None:
        return True
    dt = _normalize_utc(dt)
    if window.start and dt < window.start:
        return False
    if window.end and dt >= window.end:
        return False
    return True


# ── helpers ──────────────────────────────────────────────────────────

def _strip_html(value: str) -> str:
    return WHITESPACE_RE.sub(" ", HTML_TAG_RE.sub(" ", html.unescape(value))).strip()


def _tokenize_query(value: str) -> list[str]:
    return [
        token
        for token in re.findall(r"[a-z0-9][a-z0-9-]+", value.lower())
        if token not in STOPWORDS and len(token) > 2
    ]


# ── agent ────────────────────────────────────────────────────────────

class SearchAgent:
    """Discovers relevant cyber-incident articles from the open web.

    Uses two independent discovery channels — DuckDuckGo HTML search and
    Google News RSS — to reduce single-source fragility.  Time range is
    applied in two ways:

    1. **Query-level**: the ``time_range`` text is appended to the search
       query so both search engines factor it into ranking.
    2. **Post-filter**: hydrated articles are checked against the parsed
       ``TimeWindow`` (which handles both ``"last N years"`` and bare
       ``"2023"``-style ranges as proper intervals).
    """

    def run(self, request: SearchRequest) -> list[SearchResult]:
        search_query = self._build_search_query(request)
        limit = max(request.max_articles * 5, 10)

        primary = self._safe_source("duckduckgo", self._search_duckduckgo, search_query, limit)
        secondary = self._safe_source("google_news", self._search_google_news, search_query, limit)
        candidates = self._merge_candidates(primary, secondary)

        query_tokens = _tokenize_query(request.query)
        window = parse_time_window(request.time_range)

        # Parallel article hydration — most of the wall-clock time is
        # spent fetching and parsing HTML, so bounded concurrency helps.
        with ThreadPoolExecutor(max_workers=_HYDRATION_WORKERS) as pool:
            hydrated = list(pool.map(self._hydrate_candidate, candidates))

        scored_results: list[tuple[int, SearchResult]] = []
        seen_urls: set[str] = set()

        for article in hydrated:
            if article is None:
                continue
            if article.url.host in NOISE_DOMAINS:
                continue
            if str(article.url) in seen_urls:
                continue
            if not self._is_relevant(article, query_tokens):
                continue
            if not in_window(article.published_at, window):
                continue
            seen_urls.add(str(article.url))
            scored_results.append((self._score_result(article, query_tokens), article))

        scored_results.sort(key=lambda item: item[0], reverse=True)
        results = [article for _, article in scored_results[: request.max_articles]]
        log_event(
            logger, "search_ranked",
            candidates=len(candidates), hydrated=len(scored_results), returned=len(results),
        )
        return results

    def _build_search_query(self, request: SearchRequest) -> str:
        parts = [request.query]
        if request.time_range:
            parts.append(request.time_range)
        parts.append("(ransomware OR breach OR exploit OR CVE OR vulnerability)")
        return " ".join(parts)

    def _safe_source(self, name: str, fn, query: str, limit: int) -> list[dict]:
        try:
            return fn(query, limit=limit)
        except Exception as exc:
            log_event(logger, "source_failed", source=name, error=str(exc))
            return []

    # -- discovery channels -------------------------------------------

    def _search_duckduckgo(self, query: str, limit: int) -> list[dict]:
        url = f"https://html.duckduckgo.com/html/?q={http_client.quote(query)}"
        html_text = http_client.get_text(url)
        snippets = SNIPPET_RE.findall(html_text)
        results: list[dict] = []
        for idx, match in enumerate(RESULT_RE.finditer(html_text)):
            href = html.unescape(match.group("href"))
            title = _strip_html(match.group("title"))
            parsed = urllib.parse.urlparse(href)
            if "duckduckgo.com" in parsed.netloc:
                params = parse_qs(parsed.query)
                href = params.get("uddg", [href])[0]
            snippet = _strip_html(snippets[idx]) if idx < len(snippets) else ""
            results.append({
                "title": title, "url": href,
                "snippet": snippet, "published_at": None,
            })
            if len(results) >= limit:
                break
        return results

    def _search_google_news(self, query: str, limit: int) -> list[dict]:
        rss_url = (
            "https://news.google.com/rss/search?"
            f"q={http_client.quote(query)}&hl=en-US&gl=US&ceid=US:en"
        )
        rss_text = http_client.get_text(rss_url)
        root = ET.fromstring(rss_text)
        results: list[dict] = []
        for item in self._iter_items(root):
            title = item.findtext("title") or "Untitled"
            url = item.findtext("link") or "https://news.google.com/"
            snippet = _strip_html(item.findtext("description") or "")
            pub_date = item.findtext("pubDate")
            published_at = parsedate_to_datetime(pub_date) if pub_date else None
            results.append({
                "title": title, "url": url,
                "snippet": snippet, "published_at": published_at,
            })
            if len(results) >= limit:
                break
        return results

    def _merge_candidates(self, primary: list[dict], secondary: list[dict]) -> list[dict]:
        merged: list[dict] = []
        seen: set[str] = set()
        for candidate in [*primary, *secondary]:
            url = candidate["url"]
            title = candidate["title"].lower()
            key = f"{url}|{title}"
            if key in seen:
                continue
            seen.add(key)
            merged.append(candidate)
        return merged

    @staticmethod
    def _iter_items(root: ET.Element) -> Iterable[ET.Element]:
        channel = root.find("channel")
        if channel is None:
            return []
        return channel.findall("item")

    # -- article hydration --------------------------------------------

    def _hydrate_candidate(self, candidate: dict) -> SearchResult | None:
        url = candidate["url"]
        title = candidate["title"]
        snippet = candidate["snippet"]
        published_at = candidate["published_at"]

        try:
            html_text, final_url = http_client.get_text_with_url(
                url, headers={"Accept-Language": "en-US,en;q=0.9"},
            )
        except Exception:
            return None

        if "news.google.com" in urlparse(final_url).netloc:
            return None

        canonical_url = self._extract_canonical_url(html_text) or final_url
        article_title = self._extract_title(html_text) or title
        article_snippet = self._extract_meta_description(html_text) or snippet
        article_text = self._extract_article_text(html_text, article_title, article_snippet)
        if len(article_text) < 300:
            return None
        article_published_at = self._extract_published_at(html_text) or published_at

        return SearchResult(
            title=article_title[:300],
            url=canonical_url,
            snippet=article_snippet[:1000],
            published_at=article_published_at,
            raw_text=article_text[:12000],
        )

    # -- HTML helpers --------------------------------------------------

    @staticmethod
    def _extract_canonical_url(html_text: str) -> str | None:
        match = CANONICAL_RE.search(html_text)
        return html.unescape(match.group(1)).strip() if match else None

    @staticmethod
    def _extract_title(html_text: str) -> str | None:
        match = TITLE_RE.search(html_text)
        if not match:
            return None
        title = _strip_html(match.group(1))
        return title or None

    @staticmethod
    def _extract_meta_description(html_text: str) -> str | None:
        match = META_DESC_RE.search(html_text)
        if not match:
            return None
        description = _strip_html(match.group(1))
        return description or None

    @staticmethod
    def _extract_published_at(html_text: str) -> datetime | None:
        match = META_DATE_RE.search(html_text)
        if not match:
            return None
        value = html.unescape(match.group(1)).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(value)
            return _normalize_utc(dt)
        except Exception:
            return None

    def _extract_article_text(self, html_text: str, title: str, snippet: str) -> str:
        cleaned = SCRIPT_STYLE_RE.sub(" ", html_text)
        blocks = []
        for _, body in BLOCK_RE.findall(cleaned):
            text = _strip_html(body)
            if len(text) < 80:
                continue
            lowered = text.lower()
            if any(
                noise in lowered
                for noise in ("cookie", "subscribe", "sign in", "all rights reserved")
            ):
                continue
            blocks.append(text)

        if not blocks:
            fallback = _strip_html(cleaned)
            if len(fallback) < 300:
                return f"{title}\n\n{snippet}"
            blocks = [fallback]

        deduped: list[str] = []
        seen: set[str] = set()
        for block in blocks:
            normalized = block.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(block)

        return "\n\n".join([title, snippet, *deduped[:15]]).strip()

    # -- relevance & scoring ------------------------------------------

    def _is_relevant(self, result: SearchResult, query_tokens: list[str]) -> bool:
        haystack = f"{result.title}\n{result.snippet}\n{result.raw_text[:4000]}".lower()
        token_hits = sum(1 for token in query_tokens if token in haystack)
        cyber_hits = sum(1 for token in CYBER_KEYWORDS if token in haystack)
        if query_tokens and token_hits == 0:
            return False
        if cyber_hits == 0:
            return False
        if len(query_tokens) >= 2 and token_hits < 2 and cyber_hits < 2:
            return False
        return True

    def _score_result(self, result: SearchResult, query_tokens: list[str]) -> int:
        haystack = f"{result.title}\n{result.snippet}\n{result.raw_text[:4000]}".lower()
        title = result.title.lower()
        host = result.url.host.lower()
        score = 0
        score += 5 * sum(1 for token in query_tokens if token in title)
        score += 2 * sum(1 for token in query_tokens if token in haystack)
        score += 2 * sum(1 for token in CYBER_KEYWORDS if token in title)
        score += sum(1 for token in CYBER_KEYWORDS if token in haystack)
        score += 2 * sum(1 for hint in TRUSTED_DOMAIN_HINTS if hint in host)
        if result.published_at is not None:
            score += 1
        # Penalize low-signal pages (tag indexes, search results, archives).
        path = result.url.path.lower() if result.url.path else ""
        if any(hint in path for hint in _LOW_SIGNAL_PATH_HINTS):
            score -= 5
        return score
