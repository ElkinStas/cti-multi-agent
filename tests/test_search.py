from __future__ import annotations

from datetime import UTC, datetime, timezone, timedelta

from app.agents.search import SearchAgent, TimeWindow, in_window, parse_time_window
from app.models import SearchRequest, SearchResult


# ── TimeWindow unit tests ────────────────────────────────────────────

def test_parse_last_2_years() -> None:
    window = parse_time_window("last 2 years")
    assert window is not None
    assert window.start is not None
    assert window.end is None
    # Should be roughly 2 years ago.
    diff = datetime.now(UTC) - window.start
    assert 720 < diff.days < 740


def test_parse_bare_year_creates_interval() -> None:
    window = parse_time_window("2023")
    assert window is not None
    assert window.start == datetime(2023, 1, 1, tzinfo=UTC)
    assert window.end == datetime(2024, 1, 1, tzinfo=UTC)


def test_parse_none_returns_none() -> None:
    assert parse_time_window(None) is None
    assert parse_time_window("") is None


def test_in_window_2023_rejects_2024_article() -> None:
    window = TimeWindow(
        start=datetime(2023, 1, 1, tzinfo=UTC),
        end=datetime(2024, 1, 1, tzinfo=UTC),
    )
    assert in_window(datetime(2023, 6, 15, tzinfo=UTC), window) is True
    assert in_window(datetime(2024, 3, 1, tzinfo=UTC), window) is False
    assert in_window(datetime(2022, 12, 31, tzinfo=UTC), window) is False


def test_in_window_accepts_none_datetime() -> None:
    window = TimeWindow(start=datetime(2023, 1, 1, tzinfo=UTC), end=None)
    # Missing published_at → no constraint, accept.
    assert in_window(None, window) is True


def test_in_window_normalizes_naive_datetime() -> None:
    window = TimeWindow(
        start=datetime(2023, 1, 1, tzinfo=UTC),
        end=datetime(2024, 1, 1, tzinfo=UTC),
    )
    # Naive datetime treated as UTC.
    naive_inside = datetime(2023, 6, 1)
    assert in_window(naive_inside, window) is True


def test_in_window_normalizes_non_utc_timezone() -> None:
    window = TimeWindow(
        start=datetime(2023, 1, 1, tzinfo=UTC),
        end=datetime(2024, 1, 1, tzinfo=UTC),
    )
    # 2023-06-01 in UTC+5 → still inside 2023.
    tz_plus5 = timezone(timedelta(hours=5))
    assert in_window(datetime(2023, 6, 1, tzinfo=tz_plus5), window) is True


# ── SearchAgent integration tests ────────────────────────────────────

def test_search_agent_filters_irrelevant_results(monkeypatch) -> None:
    agent = SearchAgent()

    def fake_search(_query: str, limit: int):
        return [
            {
                "title": "MOVEit exploitation campaign - Example Security",
                "url": "https://example.com/moveit-campaign",
                "snippet": "Attackers exploited CVE-2023-34362 in MOVEit Transfer.",
                "published_at": None,
            },
            {
                "title": "Totally unrelated company milestone",
                "url": "https://example.com/marketing-post",
                "snippet": "A generic business update with no cyber content.",
                "published_at": None,
            },
        ][:limit]

    def fake_hydrate(candidate: dict):
        bodies = {
            "https://example.com/moveit-campaign": (
                "MOVEit exploitation campaign",
                "Attackers exploited CVE-2023-34362 via SQL injection.",
            ),
            "https://example.com/marketing-post": (
                "Totally unrelated company milestone",
                "This page is about revenue growth and hiring plans.",
            ),
        }
        title, text = bodies[candidate["url"]]
        return SearchResult(
            title=title, url=candidate["url"],
            snippet=candidate["snippet"], published_at=None, raw_text=text,
        )

    monkeypatch.setattr(agent, "_search_duckduckgo", fake_search)
    monkeypatch.setattr(agent, "_search_google_news", lambda _q, limit: [])
    monkeypatch.setattr(agent, "_hydrate_candidate", fake_hydrate)

    results = agent.run(SearchRequest(query="MOVEit exploitation", max_articles=5))
    assert len(results) == 1
    assert str(results[0].url) == "https://example.com/moveit-campaign"


def test_search_agent_returns_empty_when_no_results(monkeypatch) -> None:
    agent = SearchAgent()
    monkeypatch.setattr(agent, "_search_duckduckgo", lambda _q, limit: [])
    monkeypatch.setattr(agent, "_search_google_news", lambda _q, limit: [])
    assert agent.run(SearchRequest(query="obscure zero-day", max_articles=5)) == []
