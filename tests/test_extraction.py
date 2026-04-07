from __future__ import annotations

from datetime import UTC, datetime

from app.agents.extraction import ExtractionAgent
from app.models import SearchResult


def _make_result(**overrides) -> SearchResult:
    defaults = {
        "title": "Test article",
        "url": "https://example.com/article",
        "snippet": "A test snippet.",
        "published_at": datetime(2024, 6, 1, tzinfo=UTC),
        "raw_text": "Some raw text content for the article.",
    }
    defaults.update(overrides)
    return SearchResult(**defaults)


def test_heuristic_extraction_finds_cves_and_iocs() -> None:
    agent = ExtractionAgent()
    result = _make_result(
        title="Acme Hospital hit by LockBit after CVE-2023-34362 exploitation",
        snippet="Attackers used phishing and contacted evil-domain.com from 10.10.10.10.",
        raw_text=(
            "Acme Hospital said LockBit operators exploited CVE-2023-34362. "
            "The intrusion involved phishing and callback traffic to evil-domain.com and 10.10.10.10."
        ),
    )
    incident = agent._extract_heuristically(result)

    assert "CVE-2023-34362" in incident.cve_ids
    assert "10.10.10.10" in incident.iocs
    assert "evil-domain.com" in incident.iocs
    assert "news.google.com" not in incident.iocs
    assert incident.malware_family == "LockBit"
    assert incident.attack_vector == "phishing"


def test_ioc_extraction_filters_source_domain() -> None:
    agent = ExtractionAgent()
    result = _make_result(
        url="https://www.sentinelone.com/blog/clop-analysis",
        title="Clop analysis",
        snippet="Analysis of Clop ransomware.",
        raw_text="Callback to evil-c2.com. See www.sentinelone.com for details.",
    )
    incident = agent._extract_heuristically(result)
    assert "www.sentinelone.com" not in incident.iocs
    assert "evil-c2.com" in incident.iocs


def test_ioc_extraction_filters_known_noise() -> None:
    agent = ExtractionAgent()
    result = _make_result(
        title="Ransomware analysis",
        snippet="Contact outlook.com for support.",
        raw_text="Attacker used callback to malicious-c2.net and outlook.com.",
    )
    incident = agent._extract_heuristically(result)
    assert "outlook.com" not in incident.iocs
    assert "malicious-c2.net" in incident.iocs


def test_heuristic_extraction_prefers_clop_over_body_noise() -> None:
    agent = ExtractionAgent()
    result = _make_result(
        title="What we know about the MOVEit exploit and Cl0p attacks",
        snippet="The Cl0p ransomware group used a zero-day flaw in MOVEit.",
        raw_text="The article later compares the campaign with older Conti operations.",
    )
    assert agent._extract_heuristically(result).malware_family == "Clop"


def test_heuristic_extraction_no_cves_or_malware() -> None:
    agent = ExtractionAgent()
    result = _make_result(
        title="Generic cybersecurity article",
        snippet="No specific CVEs mentioned here.",
        raw_text="This is a general overview of security trends for the year.",
    )
    incident = agent._extract_heuristically(result)
    assert incident.cve_ids == []
    assert incident.malware_family is None


def test_heuristic_extraction_uses_published_date_as_fallback() -> None:
    agent = ExtractionAgent()
    result = _make_result(
        title="An incident without inline dates",
        snippet="No date patterns in this text.",
        raw_text="No date patterns in this article text either.",
        published_at=datetime(2024, 3, 15, tzinfo=UTC),
    )
    assert agent._extract_heuristically(result).date == "2024-03-15"


def test_llm_path_returns_incident_when_available(monkeypatch) -> None:
    fake_response = {
        "name": "Acme breach via Exchange",
        "date": "2024-01-10",
        "affected_organization": "Acme Corp",
        "attack_vector": "remote code execution",
        "malware_family": "BlackCat",
        "software_involved": ["Microsoft Exchange"],
        "iocs": ["10.0.0.1"],
        "cve_ids": ["CVE-2024-1234"],
        "source_summary": "Acme Corp breached via Exchange RCE.",
    }
    monkeypatch.setattr(
        "app.agents.extraction.generate_json", lambda _s, _u, **kw: fake_response
    )
    agent = ExtractionAgent()
    incident = agent._extract_with_llm(_make_result())
    assert incident is not None
    assert incident.name == "Acme breach via Exchange"
    assert "CVE-2024-1234" in incident.cve_ids


def test_llm_path_falls_back_to_none_when_llm_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.agents.extraction.generate_json", lambda _s, _u, **kw: None
    )
    assert ExtractionAgent()._extract_with_llm(_make_result()) is None


def test_known_software_detection_headline_first() -> None:
    """Software in title/snippet is preferred; body is only used as fallback."""
    agent = ExtractionAgent()
    # SolarWinds in headline → found. VMware only in body → skipped (headline had hits).
    result = _make_result(
        title="SolarWinds compromise details",
        snippet="SolarWinds Orion platform was targeted.",
        raw_text="Attackers compromised the SolarWinds build system, also impacting VMware.",
    )
    incident = agent._extract_heuristically(result)
    assert "SolarWinds" in incident.software_involved
    assert "VMware" not in incident.software_involved  # body-only, headline had hits


def test_known_software_falls_back_to_body() -> None:
    """When headline has no known software, body is checked."""
    agent = ExtractionAgent()
    result = _make_result(
        title="Critical vulnerability exploited in the wild",
        snippet="Attackers targeting enterprise file transfer solutions.",
        raw_text="The attackers exploited a flaw in MOVEit Transfer to exfiltrate data.",
    )
    incident = agent._extract_heuristically(result)
    assert "MOVEit" in incident.software_involved


def test_vpn_kept_in_headline_but_filtered_from_body() -> None:
    """VPN in headline is kept (it's the primary product); VPN body-only is filtered."""
    agent = ExtractionAgent()
    # VPN in headline → kept.
    result_headline = _make_result(
        title="Fortinet VPN zero-day exploited",
        snippet="Critical VPN vulnerability allows remote code execution.",
        raw_text="Attackers exploited the VPN flaw.",
    )
    inc_h = agent._extract_heuristically(result_headline)
    assert "VPN" in inc_h.software_involved

    # VPN only in body → filtered as generic noise.
    result_body = _make_result(
        title="Critical zero-day exploited in the wild",
        snippet="Attackers targeting enterprise systems.",
        raw_text="The breach involved a VPN appliance and Fortinet products.",
    )
    inc_b = agent._extract_heuristically(result_body)
    assert "VPN" not in inc_b.software_involved
    assert "Fortinet" in inc_b.software_involved


def test_date_extraction_prefers_body_over_headline() -> None:
    """Inline dates in article body take priority over dates in title."""
    agent = ExtractionAgent()
    result = _make_result(
        title="2025-11-06 update on MOVEit breach",
        snippet="Latest news about MOVEit exploitation.",
        raw_text="The original incident occurred on 2023-06-01 when attackers exploited CVE-2023-34362.",
        published_at=None,
    )
    incident = agent._extract_heuristically(result)
    assert incident.date == "2023-06-01"
