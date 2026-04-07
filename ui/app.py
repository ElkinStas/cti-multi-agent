from __future__ import annotations

import json
import os
import time

import httpx
import streamlit as st


API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
POLL_INTERVAL_SECONDS = 2
MAX_POLLS = 30

st.set_page_config(page_title="Threat Intel Search", page_icon="🛡️", layout="wide")


# ── API helpers ──────────────────────────────────────────────────────

def submit_search(payload: dict) -> dict:
    r = httpx.post(f"{API_BASE_URL}/search", json=payload, timeout=30)
    r.raise_for_status()
    return r.json()


def fetch_status(run_id: str) -> dict:
    r = httpx.get(f"{API_BASE_URL}/search/{run_id}/status", timeout=30)
    r.raise_for_status()
    return r.json()


def fetch_report(run_id: str) -> dict:
    r = httpx.get(f"{API_BASE_URL}/search/{run_id}/report", timeout=30)
    r.raise_for_status()
    return r.json()


# ── Render helpers ───────────────────────────────────────────────────

def render_report(report: dict) -> None:
    stats = report.get("summary_stats", {})
    quality = report.get("quality_metrics", {})
    evaluation = report.get("evaluation_metrics", {})
    incidents = report.get("incidents", [])
    vulnerabilities = report.get("vulnerabilities", [])
    telemetry = report.get("pipeline_telemetry", [])
    warnings = report.get("warnings", [])

    # ── top-level metrics row ────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Incidents", stats.get("total_incidents", len(incidents)))
    c2.metric("Unique CVEs", stats.get("total_unique_cves", len(vulnerabilities)))
    c3.metric("Articles reviewed", stats.get("total_articles_reviewed", 0))
    c4.metric("CVE coverage", quality.get("incidents_with_cves", 0))

    st.divider()

    # ── tabs ─────────────────────────────────────────────────────────
    tab_report, tab_incidents, tab_metrics, tab_telemetry, tab_raw = st.tabs(
        ["📋 Report", "🔍 Incidents", "📊 Metrics", "⚙️ Pipeline", "{ } Raw JSON"]
    )

    # ── tab: report ──────────────────────────────────────────────────
    with tab_report:
        # Executive summary
        with st.container(border=True):
            st.markdown("#### Executive summary")
            st.write(report.get("executive_summary") or "No executive summary available.")

        # Key findings
        findings = report.get("key_findings", [])
        if findings:
            with st.container(border=True):
                st.markdown("#### Key findings")
                for f in findings:
                    st.markdown(f"- {f}")

        # Recommendations
        recs = report.get("recommendations", [])
        if recs:
            with st.container(border=True):
                st.markdown("#### Recommendations")
                for r in recs:
                    st.markdown(f"- {r}")

        # Warnings
        if warnings:
            st.markdown("#### Warnings")
            for w in warnings:
                st.warning(w)

    # ── tab: incidents ───────────────────────────────────────────────
    with tab_incidents:
        if not incidents:
            st.info("No incidents were extracted for this query.")
        for incident in incidents:
            with st.container(border=True):
                st.markdown(f"**{incident.get('name', 'Unnamed incident')}**")

                # Two-column layout for incident fields
                left, right = st.columns(2)
                with left:
                    st.caption("Date")
                    st.write(incident.get("date") or "Unknown")
                    st.caption("Organization")
                    st.write(incident.get("affected_organization") or "Unknown")
                    st.caption("Attack vector")
                    st.write(incident.get("attack_vector") or "Unknown")
                with right:
                    st.caption("Malware family")
                    st.write(incident.get("malware_family") or "Unknown")
                    st.caption("Software involved")
                    st.write(", ".join(incident.get("software_involved", [])) or "Unknown")
                    st.caption("IOCs")
                    iocs = incident.get("iocs", [])
                    st.write(", ".join(iocs) if iocs else "None extracted")

                # CVE refs
                cve_refs = incident.get("related_vulnerabilities", [])
                if cve_refs:
                    st.caption("Related CVEs")
                    for ref in cve_refs:
                        cvss = ref.get("cvss_score")
                        sev = ref.get("severity", "")
                        desc = ref.get("description", "")
                        label = f"**{ref['cve_id']}** — CVSS {cvss}, {sev}"
                        if desc:
                            with st.expander(label):
                                st.write(desc)
                        else:
                            st.markdown(f"- {label}")

                st.caption("Source")
                st.write(incident.get("source_url") or "—")
                with st.expander("Source summary"):
                    st.write(incident.get("source_summary") or "—")

    # ── tab: metrics ─────────────────────────────────────────────────
    with tab_metrics:
        # Evaluation metrics
        with st.container(border=True):
            st.markdown("#### Evaluation metrics")
            if evaluation.get("matched_profile"):
                st.caption(f"Matched gold profile: **{evaluation['matched_profile']}**")
            else:
                st.caption("No gold profile matched this query — showing proxy metrics only.")

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("CVE precision", evaluation.get("cve_precision", "—"))
            m2.metric("CVE recall", evaluation.get("cve_recall", "—"))
            m3.metric("CVE F1", evaluation.get("cve_f1", "—"))
            m4.metric("Field coverage", evaluation.get("field_coverage_score", "—"))

            m5, m6, m7, _ = st.columns(4)
            m5.metric("Malware recall", evaluation.get("malware_recall", "—"))
            m6.metric("Software recall", evaluation.get("software_recall", "—"))
            m7.metric("Incident count", evaluation.get("incident_count_score", "—"))

        # Quality / coverage metrics
        with st.container(border=True):
            st.markdown("#### Coverage metrics")
            n = len(incidents)
            q1, q2, q3, q4 = st.columns(4)
            q1.metric("With dates", f"{quality.get('incidents_with_dates', 0)}/{n}")
            q2.metric("With orgs", f"{quality.get('incidents_with_organizations', 0)}/{n}")
            q3.metric("With IOCs", f"{quality.get('incidents_with_iocs', 0)}/{n}")
            q4.metric("With CVEs", f"{quality.get('incidents_with_cves', 0)}/{n}")

    # ── tab: pipeline telemetry ──────────────────────────────────────
    with tab_telemetry:
        if not telemetry:
            st.info("No telemetry data available.")
        else:
            with st.container(border=True):
                st.markdown("#### Agent execution timeline")
                for t in telemetry:
                    node = t.get("node", "?")
                    dur = t.get("duration_ms", 0)
                    items_in = t.get("items_in", 0)
                    items_out = t.get("items_out", 0)
                    attempt = t.get("attempt", 1)
                    degraded = t.get("degraded", False)

                    status = "⚠️ degraded" if degraded else "✅"
                    col_name, col_time, col_io, col_status = st.columns([3, 2, 3, 1])
                    col_name.write(f"`{node}`")
                    col_time.write(f"**{dur:,}** ms")
                    col_io.write(f"in={items_in}  →  out={items_out}  (attempt {attempt})")
                    col_status.write(status)

                total_ms = sum(t.get("duration_ms", 0) for t in telemetry)
                st.caption(f"Total pipeline time: **{total_ms:,}** ms")

            if warnings:
                with st.container(border=True):
                    st.markdown("#### Warnings")
                    for w in warnings:
                        st.warning(w)

    # ── tab: raw JSON ────────────────────────────────────────────────
    with tab_raw:
        st.code(json.dumps(report, indent=2, default=str), language="json")


def render_technical_summary() -> None:
    st.markdown("---")
    with st.expander("Technical summary", expanded=False):
        st.markdown(
            """
**Architecture:** Multi-agent pipeline orchestrated with **LangGraph** as an explicit DAG

**Agents (5):**
`SearchAgent` → `ExtractionAgent` → `PostProcessingAgent` → `CVEEnrichmentAgent` → `ReportAgent`

**API:** FastAPI with async run lifecycle (`POST /search` → `GET .../status` → `GET .../report`)

**Key features:**
- DuckDuckGo HTML + Google News RSS with parallel hydration and time-range post-filtering
- LLM extraction (Claude) with one-shot prompt or deterministic heuristic fallback
- NVD CVE enrichment with rate pacing and response caching
- Incident-level CVE linkage (`related_vulnerabilities`)
- Per-node telemetry, two-level retry (HTTP + orchestrator), graceful degradation
- Separate models: haiku for extraction (cheap), sonnet for synthesis (strong)
- In-memory TTL cache for NVD and LLM responses
- 42 tests covering API, search, extraction, post-processing, enrichment, caching
"""
        )


# ── Sidebar ──────────────────────────────────────────────────────────

with st.sidebar:
    st.header("Connection")
    api_base_url = st.text_input("API base URL", value=API_BASE_URL)
    if api_base_url:
        API_BASE_URL = api_base_url.rstrip("/")
    st.caption("Run the FastAPI service first, then use this UI.")

# ── Main ─────────────────────────────────────────────────────────────

st.title("Cyber Threat Intelligence Search")
st.write(
    "Enter a threat-intelligence query, optionally narrow the time range, "
    "and let the system discover incidents, extract structured details, "
    "enrich CVEs, and assemble a final report."
)

with st.form("search_form"):
    query = st.text_input("Search query", placeholder="MOVEit exploitation")
    col_tr, col_ma = st.columns(2)
    with col_tr:
        time_range = st.text_input("Time range", placeholder="last 2 years")
    with col_ma:
        max_articles = st.slider("Max articles", min_value=1, max_value=10, value=5)
    submitted = st.form_submit_button("Run search", use_container_width=True)

if submitted:
    if not query.strip():
        st.error("A search query is required.")
    else:
        payload = {
            "query": query.strip(),
            "time_range": time_range.strip() or None,
            "max_articles": max_articles,
        }
        try:
            submission = submit_search(payload)
        except Exception as exc:
            st.error(f"Unable to submit search: {exc}")
        else:
            st.session_state["latest_run_id"] = submission["run_id"]

latest_run_id = st.session_state.get("latest_run_id")
if latest_run_id:
    st.markdown("---")
    st.caption(f"Run ID: `{latest_run_id}`")
    status_ph = st.empty()
    progress_ph = st.empty()

    final_status = None
    for attempt in range(MAX_POLLS):
        try:
            status = fetch_status(latest_run_id)
        except Exception as exc:
            status_ph.error(f"Unable to fetch status: {exc}")
            break
        final_status = status
        state = status["status"]
        progress_ph.progress(min((attempt + 1) / MAX_POLLS, 1.0))
        status_ph.info(f"Status: **{state}**")
        if state in ("COMPLETED", "FAILED"):
            break
        time.sleep(POLL_INTERVAL_SECONDS)

    if final_status:
        if final_status["status"] == "COMPLETED":
            try:
                report = fetch_report(latest_run_id)
            except Exception as exc:
                st.error(f"Run completed, but the report could not be fetched: {exc}")
            else:
                st.success("Report ready.")
                render_report(report)
        elif final_status["status"] == "FAILED":
            st.error(final_status.get("error") or "The run failed.")
        else:
            st.warning("Still processing. Try again in a moment.")

render_technical_summary()
