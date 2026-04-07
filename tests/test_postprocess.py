from __future__ import annotations

from app.agents.postprocess import PostProcessingAgent
from app.models import Incident


def _make_incident(**overrides) -> Incident:
    defaults = {
        "name": "Test incident - Site Name",
        "source_url": "https://example.com/article",
        "source_title": "Test incident - Site Name",
        "source_summary": "A summary about the incident.",
        "cve_ids": [],
        "software_involved": [],
    }
    defaults.update(overrides)
    return Incident(**defaults)


def test_title_normalization_strips_site_suffix() -> None:
    agent = PostProcessingAgent()
    result = agent.run([_make_incident(name="Big breach - SecurityWeek")], "breach")
    assert len(result) == 1
    assert result[0].name == "Big breach"


def test_deduplication_removes_same_source() -> None:
    agent = PostProcessingAgent()
    inc1 = _make_incident(name="MOVEit exploit", source_summary="moveit details")
    inc2 = _make_incident(name="MOVEit exploit", source_summary="moveit details")
    assert len(agent.run([inc1, inc2], "moveit")) == 1


def test_relevance_filters_unrelated_incidents() -> None:
    agent = PostProcessingAgent()
    relevant = _make_incident(
        name="MOVEit exploitation campaign",
        source_summary="MOVEit Transfer flaw used by attackers.",
    )
    unrelated = _make_incident(
        name="Company acquires startup",
        source_summary="A generic business merger announcement.",
    )
    result = agent.run([relevant, unrelated], "moveit exploitation")
    assert len(result) == 1
    assert result[0].name == "MOVEit exploitation campaign"


def test_relevance_works_for_log4shell_query() -> None:
    agent = PostProcessingAgent()
    relevant = _make_incident(
        name="Log4Shell impact on enterprises",
        source_summary="Log4j vulnerability CVE-2021-44228.",
        software_involved=["Log4j"],
        cve_ids=["CVE-2021-44228"],
    )
    unrelated = _make_incident(
        name="Unrelated VPN breach",
        source_summary="A VPN provider disclosed a breach unrelated to Log4j.",
    )
    result = agent.run([relevant, unrelated], "log4shell incidents")
    assert len(result) == 1


def test_zero_day_vector_replaced_when_cves_present() -> None:
    agent = PostProcessingAgent()
    inc = _make_incident(
        name="Zero-day exploit",
        attack_vector="zero-day",
        cve_ids=["CVE-2024-1234"],
        source_title="Zero-day exploit",
        source_summary="CVE-2024-1234 was exploited as a zero-day.",
    )
    result = agent.run([inc], "exploit")
    assert result[0].attack_vector == "vulnerability exploitation"


def test_empty_input_returns_empty() -> None:
    assert PostProcessingAgent().run([], "anything") == []


def test_sanitize_org_removes_title_match() -> None:
    agent = PostProcessingAgent()
    inc = _make_incident(
        name="Clop exploits MOVEit",
        affected_organization="Clop exploits MOVEit",
        source_title="Clop exploits MOVEit - SecurityWeek",
    )
    result = agent.run([inc], "clop moveit")
    assert result[0].affected_organization is None


def test_sanitize_org_removes_known_vendor() -> None:
    agent = PostProcessingAgent()
    inc = _make_incident(
        name="MOVEit exploitation",
        affected_organization="Google Threat Intelligence Group",
        source_summary="moveit exploitation details",
    )
    result = agent.run([inc], "moveit")
    assert result[0].affected_organization is None


def test_sanitize_org_removes_threat_actor_name() -> None:
    agent = PostProcessingAgent()
    inc = _make_incident(
        name="Ransomware campaign",
        affected_organization="Clop Ransomware Group",
        source_summary="ransomware campaign details",
    )
    result = agent.run([inc], "ransomware")
    assert result[0].affected_organization is None


def test_sanitize_org_keeps_real_victim() -> None:
    agent = PostProcessingAgent()
    inc = _make_incident(
        name="Acme Corp breached",
        affected_organization="Acme Corp",
        source_summary="acme corp was breached via moveit",
    )
    result = agent.run([inc], "acme breach")
    assert result[0].affected_organization == "Acme Corp"


def test_sanitize_org_removes_cyber_discussion_group() -> None:
    agent = PostProcessingAgent()
    inc = _make_incident(
        name="Oracle EBS hack victims named",
        affected_organization="Stay Intouch Cyber Weapon Discussion Group",
        source_summary="oracle ebs hack details",
    )
    result = agent.run([inc], "oracle hack")
    assert result[0].affected_organization is None


def test_sanitize_org_removes_css_garbage() -> None:
    agent = PostProcessingAgent()
    inc = _make_incident(
        name="2024 Data Breach Investigations Report",
        affected_organization="Magenta Yellow Black Default Swatch Group",
        source_summary="data breach investigation report",
    )
    result = agent.run([inc], "data breach")
    assert result[0].affected_organization is None
