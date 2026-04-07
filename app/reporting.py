from __future__ import annotations

from datetime import UTC, datetime

from app.evaluation import evaluate_report
from app.models import Incident, IncidentCVERef, NodeTelemetry, Report, Vulnerability


def _to_cve_ref(vuln: Vulnerability) -> IncidentCVERef:
    return IncidentCVERef(
        cve_id=vuln.cve_id,
        description=vuln.description,
        cvss_score=vuln.cvss_score,
        severity=vuln.severity,
    )


def build_report(
    query: str,
    incidents: list[Incident],
    vulnerabilities: list[Vulnerability],
    source_count: int,
    executive_summary: str,
    key_findings: list[str],
    recommendations: list[str],
    *,
    telemetry: list[dict] | None = None,
    warnings: list[str] | None = None,
) -> Report:
    generated_at = datetime.now(UTC)
    unique_cves = len({v.cve_id for v in vulnerabilities})

    # Hydrate incident-level CVE references so the JSON output matches
    # the expected format (each incident carries its enriched CVEs).
    vuln_by_id = {v.cve_id: v for v in vulnerabilities}
    hydrated_incidents: list[Incident] = []
    for incident in incidents:
        refs = [_to_cve_ref(vuln_by_id[cve]) for cve in incident.cve_ids if cve in vuln_by_id]
        hydrated_incidents.append(
            incident.model_copy(update={"related_vulnerabilities": refs})
        )

    incidents_with_org = sum(1 for i in hydrated_incidents if i.affected_organization)
    incidents_with_date = sum(1 for i in hydrated_incidents if i.date)
    incidents_with_iocs = sum(1 for i in hydrated_incidents if i.iocs)
    incidents_with_cves = sum(1 for i in hydrated_incidents if i.cve_ids)
    evaluation_metrics = evaluate_report(
        query=query,
        incidents=hydrated_incidents,
        vulnerabilities=vulnerabilities,
        quality_metrics={
            "incidents_with_dates": incidents_with_date,
            "incidents_with_organizations": incidents_with_org,
            "incidents_with_iocs": incidents_with_iocs,
            "incidents_with_cves": incidents_with_cves,
        },
    )

    # -- hydrate telemetry objects ------------------------------------
    pipeline_telemetry: list[NodeTelemetry] = []
    for entry in telemetry or []:
        try:
            pipeline_telemetry.append(NodeTelemetry(**entry))
        except Exception:
            pass

    # -- markdown assembly --------------------------------------------
    findings_lines = [f"- {item}" for item in key_findings] or ["- No key findings generated."]
    recommendation_lines = [f"- {item}" for item in recommendations] or [
        "- No recommendations generated."
    ]

    markdown_lines = [
        "# Threat Intelligence Report",
        "",
        f"- Generated at: {generated_at.isoformat()}",
        f"- Query: {query}",
        f"- Articles reviewed: {source_count}",
        f"- Total incidents: {len(hydrated_incidents)}",
        f"- Unique CVEs: {unique_cves}",
        "",
        "## Executive Summary",
        executive_summary or "No executive summary available.",
        "",
        "## Key Findings",
        *findings_lines,
        "",
        "## Coverage Metrics",
        f"- Incidents with dates: {incidents_with_date}/{len(hydrated_incidents) or 0}",
        f"- Incidents with organizations: {incidents_with_org}/{len(hydrated_incidents) or 0}",
        f"- Incidents with IOCs: {incidents_with_iocs}/{len(hydrated_incidents) or 0}",
        f"- Incidents with CVEs: {incidents_with_cves}/{len(hydrated_incidents) or 0}",
        "",
        "## Incidents",
    ]

    for incident in hydrated_incidents:
        markdown_lines.extend(
            [
                f"### {incident.name}",
                f"- Source: {incident.source_url}",
                f"- Date: {incident.date or 'Unknown'}",
                f"- Organization: {incident.affected_organization or 'Unknown'}",
                f"- Attack vector: {incident.attack_vector or 'Unknown'}",
                f"- Malware family: {incident.malware_family or 'Unknown'}",
                f"- Software involved: {', '.join(incident.software_involved) or 'Unknown'}",
                f"- IOCs: {', '.join(incident.iocs) or 'None extracted'}",
            ]
        )
        if incident.related_vulnerabilities:
            markdown_lines.append("- Related CVEs:")
            for ref in incident.related_vulnerabilities:
                suffix = ""
                if ref.cvss_score is not None:
                    suffix = f" (CVSS {ref.cvss_score}, {ref.severity or 'UNKNOWN'})"
                markdown_lines.append(f"  - {ref.cve_id}{suffix}")
        markdown_lines.append("")

    markdown_lines.extend(["## Recommendations", *recommendation_lines])

    if pipeline_telemetry:
        markdown_lines.extend(["", "## Pipeline Telemetry"])
        for t in pipeline_telemetry:
            status = "degraded" if t.degraded else "ok"
            markdown_lines.append(
                f"- **{t.node}**: {t.duration_ms}ms, "
                f"in={t.items_in} out={t.items_out}, "
                f"attempt={t.attempt}, status={status}"
            )

    return Report(
        query=query,
        generated_at=generated_at,
        incidents=hydrated_incidents,
        vulnerabilities=vulnerabilities,
        summary_stats={
            "total_articles_reviewed": source_count,
            "total_incidents": len(hydrated_incidents),
            "total_unique_cves": unique_cves,
        },
        quality_metrics={
            "incidents_with_dates": incidents_with_date,
            "incidents_with_organizations": incidents_with_org,
            "incidents_with_iocs": incidents_with_iocs,
            "incidents_with_cves": incidents_with_cves,
        },
        evaluation_metrics=evaluation_metrics,
        executive_summary=executive_summary,
        key_findings=key_findings,
        recommendations=recommendations,
        markdown_summary="\n".join(markdown_lines).strip(),
        pipeline_telemetry=pipeline_telemetry,
        warnings=warnings or [],
    )
