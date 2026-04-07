from __future__ import annotations

import time

from app.cache import nvd_cache
from app.clients import http_client
from app.logging_utils import get_logger, log_event
from app.models import Incident, Vulnerability

logger = get_logger("enrichment")

_NVD_REQUEST_DELAY_S = 1.0
_NVD_CACHE_TTL_S = 86400  # 24 hours


class CVEEnrichmentAgent:
    def run(self, incidents: list[Incident]) -> list[Vulnerability]:
        vulnerabilities: dict[str, Vulnerability] = {}
        cve_ids = list(dict.fromkeys(
            cve_id for incident in incidents for cve_id in incident.cve_ids
        ))
        for idx, cve_id in enumerate(cve_ids):
            # Check cache before hitting NVD.
            cache_key = f"nvd:{cve_id}"
            cached = nvd_cache.get(cache_key)
            if cached is not None:
                log_event(logger, "nvd_cache_hit", cve_id=cve_id)
                vulnerabilities[cve_id] = Vulnerability(**cached)
                continue

            if idx > 0:
                time.sleep(_NVD_REQUEST_DELAY_S)
            vuln = self._fetch_cve(cve_id)
            vulnerabilities[cve_id] = vuln
            # Only cache successful enrichments — a transient NVD failure
            # should not poison the cache for 24 hours.
            if vuln.description is not None:
                nvd_cache.set(cache_key, vuln.model_dump(), ttl_s=_NVD_CACHE_TTL_S)
        return list(vulnerabilities.values())

    def _fetch_cve(self, cve_id: str) -> Vulnerability:
        try:
            payload = http_client.get_json(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?cveId={http_client.quote(cve_id)}"
            )
            vuln = payload["vulnerabilities"][0]["cve"]
            metrics = vuln.get("metrics", {})
            cvss = None
            severity = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    metric = metrics[key][0]
                    data = metric.get("cvssData", {})
                    cvss = data.get("baseScore")
                    severity = data.get("baseSeverity") or metric.get("baseSeverity")
                    break

            products = []
            for config in vuln.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe in node.get("cpeMatch", []):
                        criteria = cpe.get("criteria")
                        if criteria:
                            products.append(criteria)

            references = [ref["url"] for ref in vuln.get("references", []) if "url" in ref]
            descriptions = vuln.get("descriptions", [])
            description = next(
                (item["value"] for item in descriptions if item.get("lang") == "en"), None
            )

            log_event(logger, "cve_enriched", cve_id=cve_id, cvss=cvss, severity=severity)
            return Vulnerability(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss,
                severity=severity,
                affected_products=products[:10],
                references=references[:10],
            )
        except Exception as exc:
            log_event(logger, "cve_enrichment_failed", cve_id=cve_id, error=str(exc))
            return Vulnerability(cve_id=cve_id)
