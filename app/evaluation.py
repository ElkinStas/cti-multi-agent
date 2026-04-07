from __future__ import annotations

import json
from pathlib import Path

from app.models import Incident, Vulnerability


EVAL_DATASET_PATH = Path(__file__).resolve().parent.parent / "examples" / "eval_dataset.json"


def _normalize_query(value: str) -> str:
    return " ".join(value.lower().strip().split())


def _safe_div(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 3)


def _f1(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return round((2 * precision * recall) / (precision + recall), 3)


def _load_eval_profiles() -> dict[str, dict]:
    try:
        rows = json.loads(EVAL_DATASET_PATH.read_text())
    except Exception:
        return {}
    return {_normalize_query(row["query"]): row for row in rows}


def evaluate_report(
    query: str,
    incidents: list[Incident],
    vulnerabilities: list[Vulnerability],
    quality_metrics: dict[str, int],
) -> dict[str, float | int | str | None]:
    profiles = _load_eval_profiles()
    profile = profiles.get(_normalize_query(query))
    extracted_cves = sorted({v.cve_id for v in vulnerabilities})
    extracted_malware = sorted({i.malware_family for i in incidents if i.malware_family})
    extracted_software = sorted({s for i in incidents for s in i.software_involved})

    if profile is None:
        return {
            "matched_profile": None,
            "cve_precision": None,
            "cve_recall": None,
            "cve_f1": None,
            "malware_recall": None,
            "software_recall": None,
            "incident_count_score": None,
            "field_coverage_score": round(
                (
                    quality_metrics.get("incidents_with_dates", 0)
                    + quality_metrics.get("incidents_with_organizations", 0)
                    + quality_metrics.get("incidents_with_iocs", 0)
                    + quality_metrics.get("incidents_with_cves", 0)
                )
                / max(len(incidents) * 4, 1),
                3,
            ),
        }

    expected_cves = sorted(set(profile.get("expected_cves", [])))
    expected_malware = sorted(set(profile.get("expected_malware", [])))
    expected_software = sorted(set(profile.get("expected_software", [])))
    min_incidents = int(profile.get("min_incidents", 0))

    matched_cves = len(set(extracted_cves) & set(expected_cves))
    cve_precision = _safe_div(matched_cves, len(extracted_cves))
    cve_recall = _safe_div(matched_cves, len(expected_cves))

    matched_malware = len(set(extracted_malware) & set(expected_malware))
    malware_recall = (
        _safe_div(matched_malware, len(expected_malware)) if expected_malware else 1.0
    )

    matched_software = len(set(extracted_software) & set(expected_software))
    software_recall = (
        _safe_div(matched_software, len(expected_software)) if expected_software else 1.0
    )

    incident_count_score = (
        1.0 if len(incidents) >= min_incidents else _safe_div(len(incidents), min_incidents)
    )
    field_coverage_score = round(
        (
            quality_metrics.get("incidents_with_dates", 0)
            + quality_metrics.get("incidents_with_organizations", 0)
            + quality_metrics.get("incidents_with_iocs", 0)
            + quality_metrics.get("incidents_with_cves", 0)
        )
        / max(len(incidents) * 4, 1),
        3,
    )

    return {
        "matched_profile": profile["query"],
        "cve_precision": cve_precision,
        "cve_recall": cve_recall,
        "cve_f1": _f1(cve_precision, cve_recall),
        "malware_recall": malware_recall,
        "software_recall": software_recall,
        "incident_count_score": incident_count_score,
        "field_coverage_score": field_coverage_score,
        "expected_cve_count": len(expected_cves),
        "extracted_cve_count": len(extracted_cves),
    }
