from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from app.config import settings
from app.llm import generate_json
from app.models import Incident, SearchResult


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9.-]+\.(?:com|net|org|io|ru|cn|biz|info)\b")
DATE_RE = re.compile(r"\b(20\d{2}-\d{2}-\d{2})\b")
ORG_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*){0,4}"
    r"\s+(?:Inc|Corp|LLC|Ltd|Group|Hospital|Health|Bank))\b"
)
MALWARE_PATTERNS = [
    ("Clop", re.compile(r"\bcl[o0]p\b", re.I)),
    ("LockBit", re.compile(r"\blockbit\b", re.I)),
    ("BlackCat", re.compile(r"\bblackcat\b|\balphv\b", re.I)),
    ("Akira", re.compile(r"\bakira\b", re.I)),
    ("Conti", re.compile(r"\bconti\b", re.I)),
    ("Ryuk", re.compile(r"\bryuk\b", re.I)),
]
ATTACK_VECTOR_PATTERNS = [
    "sql injection",
    "remote code execution",
    "zero-day",
    "phishing",
    "stolen credentials",
    "credential stuffing",
    "supply chain",
    "vulnerability exploitation",
]
IOC_NOISE_DOMAINS = {
    "accounts.google.com", "google.com", "myaccount.google.com",
    "news.google.com", "news.url.google.com", "support.google.com",
    "www.google.com", "www.gstatic.com", "twitter.com", "x.com",
    "facebook.com", "linkedin.com", "youtube.com",
    # Common non-IOC domains that leak through article text.
    "outlook.com", "gmail.com", "yahoo.com", "hotmail.com",
    "sentinelone.com", "www.sentinelone.com",
    "crowdstrike.com", "www.crowdstrike.com",
    "mandiant.com", "www.mandiant.com",
    "trendmicro.com", "www.trendmicro.com",
    "paloaltonetworks.com", "unit42.paloaltonetworks.com",
    "microsoft.com", "www.microsoft.com",
    "bleepingcomputer.com", "www.bleepingcomputer.com",
    "thehackernews.com", "www.thehackernews.com",
    "securityweek.com", "www.securityweek.com",
    "therecord.media", "www.therecord.media",
}
KNOWN_SOFTWARE = (
    "Exchange", "MOVEit", "Fortinet", "Citrix", "Ivanti", "VPN",
    "ScreenConnect", "SolarWinds", "Log4j", "Apache", "Confluence",
    "VMware", "Barracuda", "PaperCut", "Cisco",
)
# Terms too generic to be useful as the primary affected product unless
# they appear in the headline zone.
_GENERIC_SOFTWARE_NOISE = {"VPN"}
ORG_FALLBACK_SUFFIXES = (
    "inc", "corp", "llc", "ltd", "group", "hospital", "health",
    "bank", "university", "systems", "software",
)
BAD_ORG_PREFIXES = ("source ", "learn ", "what ", "how ", "why ", "the ")

_LLM_EXTRACTION_EXAMPLE = """\
Example output:
{
  "name": "Acme Corp ransomware attack",
  "date": "2024-03-15",
  "affected_organization": "Acme Corp",
  "attack_vector": "phishing email with malicious attachment",
  "malware_family": "LockBit 3.0",
  "software_involved": ["Microsoft Exchange Server"],
  "iocs": ["185.220.101.42", "evil-domain.com"],
  "cve_ids": ["CVE-2023-36745"],
  "source_summary": "Acme Corp disclosed a LockBit ransomware incident exploiting CVE-2023-36745."
}

Rules:
- affected_organization must be the VICTIM or impacted entity, not the publisher, \
analyst firm, security vendor, or threat actor group. If unsure, return null.
- Do not use the article title as affected_organization.
- software_involved must list only software that was EXPLOITED, AFFECTED, or \
TARGETED in the incident — not every product mentioned in the article.
- iocs must be actual indicators of compromise (malicious IPs, domains, hashes). \
Do not include the source website domain, email providers, or security vendor domains."""

_EXTRACTION_WORKERS = 4


class ExtractionAgent:
    def run(self, results: list[SearchResult]) -> list[Incident]:
        with ThreadPoolExecutor(max_workers=_EXTRACTION_WORKERS) as pool:
            return list(pool.map(self._extract_one, results))

    def _extract_one(self, result: SearchResult) -> Incident:
        incident = self._extract_with_llm(result)
        if incident is None:
            incident = self._extract_heuristically(result)
        return incident

    def _extract_with_llm(self, result: SearchResult) -> Incident | None:
        text_limit = settings.max_llm_chars_per_article
        prompt = (
            "Extract a cybersecurity incident into JSON with keys: "
            "name, date, affected_organization, attack_vector, malware_family, "
            "software_involved, iocs, cve_ids, source_summary. "
            "Use null or empty lists when unknown.\n\n"
            f"{_LLM_EXTRACTION_EXAMPLE}\n\n"
            f"Title: {result.title}\n"
            f"Snippet: {result.snippet}\n"
            f"Article text:\n{result.raw_text[:text_limit]}"
        )
        data = generate_json(
            "You extract structured cybersecurity intelligence from web articles.",
            prompt,
            model=settings.anthropic_extraction_model,
        )
        try:
            if data is None:
                return None
            return Incident(
                name=data.get("name") or result.title,
                date=data.get("date"),
                affected_organization=data.get("affected_organization"),
                attack_vector=data.get("attack_vector"),
                malware_family=data.get("malware_family"),
                software_involved=data.get("software_involved") or [],
                iocs=data.get("iocs") or [],
                cve_ids=[cve.upper() for cve in data.get("cve_ids") or []],
                source_url=result.url,
                source_title=result.title,
                source_summary=data.get("source_summary") or result.snippet,
            )
        except Exception:
            return None

    def _extract_heuristically(self, result: SearchResult) -> Incident:
        text = f"{result.title}\n{result.snippet}\n{result.raw_text}"
        cves = sorted({match.upper() for match in CVE_RE.findall(text)})
        iocs = self._extract_iocs(text, str(result.url))
        affected_org = self._extract_org(text, result.title)
        malware_family = self._extract_malware(result.title, result.snippet, result.raw_text)
        attack_vector = self._extract_attack_vector(
            result.title, result.snippet, result.raw_text
        )
        # Search for inline dates in article body first (closer to incident
        # description) then fall back to title/snippet, then published_at.
        body_date = DATE_RE.search(result.raw_text)
        headline_date = DATE_RE.search(f"{result.title}\n{result.snippet}")
        date = (
            body_date.group(1) if body_date
            else headline_date.group(1) if headline_date
            else (result.published_at.date().isoformat() if result.published_at else None)
        )

        # Prefer software found in title/snippet (high signal) over body
        # (which may mention many products tangentially).
        headline = f"{result.title}\n{result.snippet}".lower()
        software = [kw for kw in KNOWN_SOFTWARE if kw.lower() in headline]
        if not software:
            body_software = [kw for kw in KNOWN_SOFTWARE if kw.lower() in result.raw_text.lower()]
            # Drop generic terms only from body fallback — if VPN is in the
            # headline, it's likely the primary product.
            software = [s for s in body_software if s not in _GENERIC_SOFTWARE_NOISE]

        return Incident(
            name=result.title,
            date=date,
            affected_organization=affected_org,
            attack_vector=attack_vector,
            malware_family=malware_family,
            software_involved=software,
            iocs=iocs,
            cve_ids=cves,
            source_url=result.url,
            source_title=result.title,
            source_summary=result.snippet,
        )

    def _extract_iocs(self, text: str, source_url: str = "") -> list[str]:
        # Extract the source article's hostname so we can exclude it.
        source_host = ""
        try:
            from urllib.parse import urlparse
            source_host = urlparse(source_url).hostname or ""
        except Exception:
            pass

        raw_domains = {value.lower() for value in DOMAIN_RE.findall(text)}
        filtered_domains = [
            domain
            for domain in raw_domains
            if domain not in IOC_NOISE_DOMAINS
            and not domain.endswith(".gov")
            and not domain.endswith(".edu")
            and not (source_host and domain.endswith(source_host))
        ]
        return sorted(set(IP_RE.findall(text)).union(filtered_domains))[:10]

    def _extract_org(self, text: str, title: str) -> str | None:
        org_match = ORG_RE.search(text)
        if org_match:
            org = org_match.group(1).strip()
            if not org.lower().startswith(BAD_ORG_PREFIXES):
                return org
        title_prefix = re.split(r"\s+-\s+|\s+\|\s+", title)[0].strip()
        words = title_prefix.split()
        if len(words) >= 2 and any(
            words[-1].lower().rstrip(".,") == suffix for suffix in ORG_FALLBACK_SUFFIXES
        ):
            if not title_prefix.lower().startswith(BAD_ORG_PREFIXES):
                return title_prefix
        return None

    def _extract_malware(self, title: str, snippet: str, raw_text: str) -> str | None:
        for haystack in (f"{title}\n{snippet}", raw_text):
            for name, pattern in MALWARE_PATTERNS:
                if pattern.search(haystack):
                    return name
        return None

    def _extract_attack_vector(self, title: str, snippet: str, raw_text: str) -> str | None:
        haystacks = (f"{title}\n{snippet}".lower(), raw_text.lower())
        for haystack in haystacks:
            for pattern in ATTACK_VECTOR_PATTERNS:
                if pattern in haystack:
                    return pattern
        return None
