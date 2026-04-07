from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field, HttpUrl, field_validator

from app.config import settings


def utc_now() -> datetime:
    return datetime.now(UTC)


class RunStatus(str, Enum):
    pending = "PENDING"
    running = "RUNNING"
    completed = "COMPLETED"
    failed = "FAILED"


class SearchRequest(BaseModel):
    query: str = Field(min_length=3, description="Threat intelligence search query")
    time_range: str | None = Field(
        default=None,
        description="Optional free-text time range such as 'last 2 years' or '2023'.",
    )
    max_articles: int = Field(default=settings.default_max_articles, ge=1, le=10)

    @field_validator("query")
    @classmethod
    def query_must_have_content(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("query must contain at least 3 non-whitespace characters")
        return v


class SearchResult(BaseModel):
    title: str
    url: HttpUrl
    snippet: str
    published_at: datetime | None = None
    raw_text: str


class IncidentCVERef(BaseModel):
    """Lightweight CVE reference embedded inside an incident for direct
    incident-to-vulnerability inspection (matches the expected output
    format from the assignment)."""

    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    severity: str | None = None


class Incident(BaseModel):
    name: str
    date: str | None = None
    affected_organization: str | None = None
    attack_vector: str | None = None
    malware_family: str | None = None
    software_involved: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    related_vulnerabilities: list[IncidentCVERef] = Field(default_factory=list)
    source_url: HttpUrl
    source_title: str
    source_summary: str


class Vulnerability(BaseModel):
    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    severity: str | None = None
    affected_products: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    known_exploited: bool | None = None


class NodeTelemetry(BaseModel):
    """Per-node execution telemetry for observability."""

    node: str
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    items_in: int
    items_out: int
    attempt: int = 1
    degraded: bool = False
    error: str | None = None


class Report(BaseModel):
    query: str
    generated_at: datetime
    incidents: list[Incident]
    vulnerabilities: list[Vulnerability]
    summary_stats: dict[str, int]
    quality_metrics: dict[str, int]
    evaluation_metrics: dict[str, float | int | str | None]
    executive_summary: str
    key_findings: list[str]
    recommendations: list[str]
    markdown_summary: str
    pipeline_telemetry: list[NodeTelemetry] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RunState(BaseModel):
    run_id: str
    status: RunStatus
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    request: SearchRequest
    report: Report | None = None
    error: str | None = None


class SubmitRunResponse(BaseModel):
    run_id: str
    status: RunStatus


class StatusResponse(BaseModel):
    run_id: str
    status: RunStatus
    error: str | None = None
    updated_at: datetime
