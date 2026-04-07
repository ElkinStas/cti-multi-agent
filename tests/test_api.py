from __future__ import annotations

import time
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.main import app
from app.models import Incident, IncidentCVERef, Report, Vulnerability


def _make_fake_report(query: str) -> Report:
    return Report(
        query=query,
        generated_at=datetime(2026, 4, 1, tzinfo=UTC),
        incidents=[
            Incident(
                name="MOVEit exploitation campaign",
                date="2023-06-01",
                affected_organization="Example Corp",
                attack_vector="remote code execution",
                malware_family=None,
                software_involved=["MOVEit"],
                iocs=[],
                cve_ids=["CVE-2023-34362"],
                related_vulnerabilities=[
                    IncidentCVERef(
                        cve_id="CVE-2023-34362",
                        description="MOVEit Transfer SQL injection",
                        cvss_score=9.8,
                        severity="CRITICAL",
                    )
                ],
                source_url="https://example.com/incidents/moveit",
                source_title="MOVEit exploitation campaign",
                source_summary="Sample summary",
            )
        ],
        vulnerabilities=[
            Vulnerability(
                cve_id="CVE-2023-34362",
                description="MOVEit Transfer SQL injection",
                cvss_score=9.8,
                severity="CRITICAL",
            )
        ],
        summary_stats={"total_incidents": 1, "total_unique_cves": 1},
        quality_metrics={
            "incidents_with_dates": 1,
            "incidents_with_organizations": 1,
            "incidents_with_iocs": 0,
            "incidents_with_cves": 1,
        },
        evaluation_metrics={
            "matched_profile": "MOVEit exploitation",
            "cve_precision": 1.0,
            "cve_recall": 1.0,
            "cve_f1": 1.0,
            "malware_recall": 1.0,
            "software_recall": 1.0,
            "incident_count_score": 1.0,
            "field_coverage_score": 0.75,
        },
        executive_summary="A concise executive summary.",
        key_findings=["One key finding."],
        recommendations=["One recommendation."],
        markdown_summary="# Threat Intelligence Report",
    )


def test_search_lifecycle(monkeypatch) -> None:
    async def fake_run(request, run_id):
        return _make_fake_report(request.query)

    monkeypatch.setattr("app.main.orchestrator.run", fake_run)

    with TestClient(app) as client:
        resp = client.post("/search", json={"query": "MOVEit exploitation", "max_articles": 1})
        assert resp.status_code == 202

        run_id = resp.json()["run_id"]
        time.sleep(0.3)

        status = client.get(f"/search/{run_id}/status")
        assert status.status_code == 200
        assert status.json()["status"] == "COMPLETED"

        report = client.get(f"/search/{run_id}/report")
        assert report.status_code == 200
        body = report.json()
        assert body["summary_stats"]["total_unique_cves"] == 1
        assert len(body["incidents"]) == 1
        # Incident carries enriched CVE refs.
        assert body["incidents"][0]["related_vulnerabilities"][0]["cve_id"] == "CVE-2023-34362"


def test_status_not_found() -> None:
    with TestClient(app) as client:
        assert client.get("/search/nonexistent-id/status").status_code == 404


def test_report_not_found() -> None:
    with TestClient(app) as client:
        assert client.get("/search/nonexistent-id/report").status_code == 404


def test_submit_invalid_query() -> None:
    with TestClient(app) as client:
        assert client.post("/search", json={"query": "ab"}).status_code == 422


def test_health() -> None:
    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
