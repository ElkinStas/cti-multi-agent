from __future__ import annotations

from app.agents.enrichment import CVEEnrichmentAgent
from app.models import Incident


def _fake_nvd_response():
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-34362",
                    "descriptions": [
                        {"lang": "en", "value": "MOVEit Transfer SQL injection vulnerability."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {"criteria": "cpe:2.3:a:progress:moveit_transfer:*"}
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-34362"}
                    ],
                }
            }
        ]
    }


def test_fetch_cve_falls_back_on_network_error(monkeypatch) -> None:
    agent = CVEEnrichmentAgent()

    def boom(_url: str, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr("app.agents.enrichment.http_client.get_json", boom)
    vuln = agent._fetch_cve("CVE-2023-0001")
    assert vuln.cve_id == "CVE-2023-0001"
    assert vuln.description is None


def test_fetch_cve_parses_nvd_response(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.agents.enrichment.http_client.get_json", lambda _u, **kw: _fake_nvd_response()
    )
    vuln = CVEEnrichmentAgent()._fetch_cve("CVE-2023-34362")
    assert vuln.cvss_score == 9.8
    assert vuln.severity == "CRITICAL"
    assert "moveit_transfer" in vuln.affected_products[0]


def test_run_deduplicates_cve_ids(monkeypatch) -> None:
    monkeypatch.setattr("app.agents.enrichment._NVD_REQUEST_DELAY_S", 0)

    call_count = 0

    def counting_fetch(_url: str, **kwargs):
        nonlocal call_count
        call_count += 1
        return _fake_nvd_response()

    monkeypatch.setattr("app.agents.enrichment.http_client.get_json", counting_fetch)
    # Clear cache so this test is isolated.
    monkeypatch.setattr("app.agents.enrichment.nvd_cache", __import__("app.cache", fromlist=["SimpleCache"]).SimpleCache())

    incidents = [
        Incident(
            name="Inc1", cve_ids=["CVE-2023-34362"],
            source_url="https://a.com", source_title="A", source_summary="A",
        ),
        Incident(
            name="Inc2", cve_ids=["CVE-2023-34362"],
            source_url="https://b.com", source_title="B", source_summary="B",
        ),
    ]
    vulns = CVEEnrichmentAgent().run(incidents)
    assert len(vulns) == 1
    assert call_count == 1


def test_cache_avoids_repeated_nvd_calls(monkeypatch) -> None:
    monkeypatch.setattr("app.agents.enrichment._NVD_REQUEST_DELAY_S", 0)

    from app.cache import SimpleCache
    fresh_cache = SimpleCache()
    monkeypatch.setattr("app.agents.enrichment.nvd_cache", fresh_cache)

    call_count = 0

    def counting_fetch(_url: str, **kwargs):
        nonlocal call_count
        call_count += 1
        return _fake_nvd_response()

    monkeypatch.setattr("app.agents.enrichment.http_client.get_json", counting_fetch)

    agent = CVEEnrichmentAgent()
    inc = [Incident(
        name="Inc", cve_ids=["CVE-2023-34362"],
        source_url="https://a.com", source_title="A", source_summary="A",
    )]

    # First call → NVD fetch.
    agent.run(inc)
    assert call_count == 1

    # Second call → cache hit, no additional fetch.
    agent.run(inc)
    assert call_count == 1
