from __future__ import annotations

import re
from urllib.parse import urlparse

from app.models import Incident


TITLE_SITE_SUFFIX_RE = re.compile(r"\s+(?:-|\|)\s+[^-|]+$")
BAD_TITLE_PREFIXES = ("#stopransomware:",)

# Known security vendors / publishers / analyst orgs that should never
# be treated as the "affected organization" in an incident.
_KNOWN_NON_VICTIM_ORGS = {
    "google threat intelligence", "google threat intelligence group",
    "mandiant", "crowdstrike", "palo alto networks", "unit 42",
    "sentinelone", "trendmicro", "trend micro", "microsoft",
    "cisco talos", "recorded future", "sophos", "kaspersky",
    "symantec", "broadcom", "checkpoint", "fortinet",
    "cisa", "nist", "fbi", "nsa",
}

_RELEVANCE_STOPWORDS = {
    "a", "an", "and", "attacks", "breach", "data", "for", "in", "last",
    "of", "on", "or", "sector", "the", "to", "with", "years",
}


def _query_tokens(query: str) -> list[str]:
    return [
        t for t in re.findall(r"[a-z0-9][a-z0-9-]+", query.lower())
        if t not in _RELEVANCE_STOPWORDS and len(t) > 2
    ]


class PostProcessingAgent:
    def run(self, incidents: list[Incident], query: str) -> list[Incident]:
        cleaned: list[Incident] = []
        seen_keys: set[str] = set()
        tokens = _query_tokens(query)

        for incident in incidents:
            normalized = self._normalize_incident(incident)
            if not self._is_incident_relevant(normalized, tokens):
                continue
            key = self._dedup_key(normalized)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            cleaned.append(normalized)
        return cleaned

    def _normalize_incident(self, incident: Incident) -> Incident:
        name = TITLE_SITE_SUFFIX_RE.sub("", incident.name).strip()
        lowered = name.lower()
        for prefix in BAD_TITLE_PREFIXES:
            if lowered.startswith(prefix):
                name = name[len(prefix):].strip()
                break

        cve_ids = self._filter_cves(incident)
        attack_vector = incident.attack_vector
        if attack_vector == "zero-day" and cve_ids:
            attack_vector = "vulnerability exploitation"

        org = self._sanitize_org(incident, name)

        return incident.model_copy(
            update={
                "name": name,
                "attack_vector": attack_vector,
                "cve_ids": cve_ids,
                "affected_organization": org,
            }
        )

    @staticmethod
    def _sanitize_org(incident: Incident, normalized_name: str) -> str | None:
        """Drop affected_organization when it looks like a publisher, analyst
        firm, threat actor name, or was copied from the article title."""
        org = incident.affected_organization
        if not org:
            return None
        org_lower = org.strip().lower()
        title_lower = incident.source_title.strip().lower()
        name_lower = normalized_name.strip().lower()

        # Org matches the article title or incident name → likely copy-paste.
        if org_lower == title_lower or org_lower == name_lower:
            return None
        # Too long to be a real org name → probably a sentence fragment.
        if len(org.split()) > 6:
            return None
        # Known security vendors / analysts / publishers.
        if org_lower in _KNOWN_NON_VICTIM_ORGS:
            return None
        # Threat actor / cyber / discussion group name leaked into org.
        if any(kw in org_lower for kw in (
            "ransomware", "threat", "apt", "hackers", "cyber",
            "discussion", "advisory", "intelligence",
        )):
            return None
        # HTML/CSS garbage that leaked through regex (color names, CSS terms).
        _GARBAGE_TOKENS = {
            "magenta", "yellow", "cyan", "default", "swatch",
            "serif", "bold", "italic", "rgba", "transparent",
            "undefined", "null", "none", "template",
        }
        org_tokens = set(org_lower.split())
        if org_tokens & _GARBAGE_TOKENS:
            return None
        return org.strip()

    def _filter_cves(self, incident: Incident) -> list[str]:
        title_and_summary = f"{incident.source_title}\n{incident.source_summary}".upper()
        mentioned = [cve for cve in incident.cve_ids if cve.upper() in title_and_summary]
        if mentioned:
            return sorted(set(mentioned))
        if len(incident.cve_ids) <= 1:
            return incident.cve_ids
        return sorted(set(incident.cve_ids[:1]))

    def _is_incident_relevant(self, incident: Incident, query_tokens: list[str]) -> bool:
        if not query_tokens:
            return True
        haystack = (
            f"{incident.name}\n{incident.source_summary}\n"
            f"{' '.join(incident.software_involved)}\n{' '.join(incident.cve_ids)}"
        ).lower()
        return sum(1 for t in query_tokens if t in haystack) > 0

    def _dedup_key(self, incident: Incident) -> str:
        primary_cve = incident.cve_ids[0] if incident.cve_ids else ""
        host = urlparse(str(incident.source_url)).netloc
        malware = incident.malware_family or ""
        software = ",".join(sorted(incident.software_involved))
        return f"{primary_cve}|{malware}|{software}|{host}|{incident.name.lower()}"
