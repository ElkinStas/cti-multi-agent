from __future__ import annotations

import json
from collections import Counter

from app.config import settings
from app.llm import generate_json
from app.models import Incident, Vulnerability


class ReportAgent:
    def run(
        self,
        query: str,
        incidents: list[Incident],
        vulnerabilities: list[Vulnerability],
    ) -> dict[str, object]:
        llm_summary = self._generate_with_llm(query, incidents, vulnerabilities)
        if llm_summary is not None:
            return llm_summary
        return self._generate_heuristically(query, incidents, vulnerabilities)

    def _generate_with_llm(
        self,
        query: str,
        incidents: list[Incident],
        vulnerabilities: list[Vulnerability],
    ) -> dict[str, object] | None:
        compact_incidents = [
            {
                "name": inc.name,
                "date": inc.date,
                "affected_organization": inc.affected_organization,
                "attack_vector": inc.attack_vector,
                "malware_family": inc.malware_family,
                "software_involved": inc.software_involved,
                "cve_ids": inc.cve_ids,
                "source_summary": inc.source_summary,
            }
            for inc in incidents
        ]
        compact_vulns = [
            {
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
                "severity": v.severity,
                "description": v.description,
            }
            for v in vulnerabilities
        ]
        prompt = (
            "Create a threat intelligence synthesis from the extracted incidents "
            "and vulnerabilities. Return JSON with keys: executive_summary, "
            "key_findings, recommendations. Each of key_findings and "
            "recommendations must be a short list of strings.\n\n"
            f"Query: {query}\n"
            f"Incidents:\n{json.dumps(compact_incidents, ensure_ascii=False, indent=1)}\n\n"
            f"Vulnerabilities:\n{json.dumps(compact_vulns, ensure_ascii=False, indent=1)}"
        )
        return generate_json(
            "You are a senior cyber threat intelligence analyst.",
            prompt,
            model=settings.anthropic_report_model,
        )

    def _generate_heuristically(
        self,
        query: str,
        incidents: list[Incident],
        vulnerabilities: list[Vulnerability],
    ) -> dict[str, object]:
        malware_ctr = Counter(i.malware_family for i in incidents if i.malware_family)
        attack_ctr = Counter(i.attack_vector for i in incidents if i.attack_vector)
        top_malware = malware_ctr.most_common(1)[0][0] if malware_ctr else None
        top_attack = attack_ctr.most_common(1)[0][0] if attack_ctr else None
        highest_cvss = max(
            (v.cvss_score for v in vulnerabilities if v.cvss_score is not None), default=None
        )
        critical_count = sum(
            1 for v in vulnerabilities if (v.severity or "").upper() == "CRITICAL"
        )

        executive_summary = (
            f"The system reviewed {len(incidents)} relevant sources for '{query}' "
            f"and identified {len(vulnerabilities)} unique CVEs. "
            f"{'The most common malware family was ' + top_malware + '. ' if top_malware else ''}"
            f"{'The dominant attack pattern was ' + top_attack + '. ' if top_attack else ''}"
            f"{f'The highest observed CVSS score was {highest_cvss}. ' if highest_cvss is not None else ''}"
        ).strip()

        key_findings = [
            f"Collected {len(incidents)} relevant incident sources tied to the query.",
            f"Mapped {len(vulnerabilities)} unique CVEs from the reviewed materials.",
            f"Observed {critical_count} critical vulnerabilities in the current result set.",
        ]
        if top_malware:
            key_findings.append(f"Most frequently referenced malware family: {top_malware}.")
        if top_attack:
            key_findings.append(f"Most common attack vector in extracted records: {top_attack}.")

        recommendations = [
            "Prioritize patching the highest-severity CVEs linked to the query.",
            "Review the primary affected software versions and exposed internet-facing instances.",
            "Validate whether any referenced exploited CVEs appear in your internal asset inventory.",
        ]

        return {
            "executive_summary": executive_summary,
            "key_findings": key_findings[:5],
            "recommendations": recommendations,
        }
