from __future__ import annotations

import operator
import time
from datetime import UTC, datetime
from typing import Annotated, Any, Callable

import httpx
from typing_extensions import TypedDict

from langgraph.graph import END, START, StateGraph

from app.logging_utils import get_logger, log_event
from app.models import (
    Incident, NodeTelemetry, Report, SearchRequest, SearchResult, Vulnerability,
)
from app.agents.enrichment import CVEEnrichmentAgent
from app.agents.extraction import ExtractionAgent
from app.agents.postprocess import PostProcessingAgent
from app.agents.report import ReportAgent
from app.agents.search import SearchAgent

_NODE_RETRY_BUDGET = 1


def _is_retryable(exc: Exception) -> bool:
    """Return True for transient / transport errors worth retrying.

    Deterministic failures (parse errors, schema errors, data issues)
    are not retried — they will fail identically on the next attempt.
    """
    return isinstance(
        exc,
        (
            httpx.TimeoutException,
            httpx.ConnectError,
            httpx.RemoteProtocolError,
            ConnectionError,
            TimeoutError,
            OSError,
        ),
    )


class AgentState(TypedDict):
    run_id: str
    request: SearchRequest
    search_results: list[SearchResult]
    incidents: list[Incident]
    vulnerabilities: list[Vulnerability]
    analysis: dict[str, object]
    report: Report | None
    errors: Annotated[list[str], operator.add]
    telemetry: Annotated[list[dict], operator.add]
    warnings: Annotated[list[str], operator.add]


class ThreatIntelOrchestrator:
    def __init__(self) -> None:
        self.search_agent = SearchAgent()
        self.extraction_agent = ExtractionAgent()
        self.postprocess_agent = PostProcessingAgent()
        self.enrichment_agent = CVEEnrichmentAgent()
        self.report_agent = ReportAgent()
        self.logger = get_logger("orchestrator")
        graph = StateGraph(AgentState)
        graph.add_node("search_agent", self._search_node)
        graph.add_node("extraction_agent", self._extraction_node)
        graph.add_node("postprocess_agent", self._postprocess_node)
        graph.add_node("cve_enrichment_agent", self._enrichment_node)
        graph.add_node("report_agent", self._analysis_node)
        graph.add_node("report_builder", self._report_node)
        graph.add_edge(START, "search_agent")
        graph.add_edge("search_agent", "extraction_agent")
        graph.add_edge("extraction_agent", "postprocess_agent")
        graph.add_edge("postprocess_agent", "cve_enrichment_agent")
        graph.add_edge("cve_enrichment_agent", "report_agent")
        graph.add_edge("report_agent", "report_builder")
        graph.add_edge("report_builder", END)
        self.graph = graph.compile()

    async def run(self, request: SearchRequest, run_id: str) -> Report:
        initial_state: AgentState = {
            "run_id": run_id,
            "request": request,
            "search_results": [],
            "incidents": [],
            "vulnerabilities": [],
            "analysis": {},
            "report": None,
            "errors": [],
            "telemetry": [],
            "warnings": [],
        }
        # LangGraph dispatches sync node functions into a thread-pool
        # executor when invoked via ainvoke(), so blocking HTTP inside
        # agents does not stall the FastAPI event loop.
        final_state = await self.graph.ainvoke(initial_state)
        if final_state["report"] is None:
            raise RuntimeError(
                "; ".join(final_state["errors"]) or "Report generation failed"
            )
        return final_state["report"]

    # -- node telemetry + retry helper --------------------------------

    def _timed_node(
        self,
        node_name: str,
        state: AgentState,
        fn: Callable[[], dict[str, Any]],
        fallback: Callable[[], dict[str, Any]],
        items_in: int,
    ) -> dict:
        last_exc: Exception | None = None
        for attempt in range(1, _NODE_RETRY_BUDGET + 2):
            started_at = datetime.now(UTC)
            start_mono = time.monotonic()
            try:
                result = fn()
                duration_ms = int((time.monotonic() - start_mono) * 1000)
                items_out = self._count_items(node_name, result)
                log_event(
                    self.logger, f"{node_name}_completed",
                    run_id=state["run_id"], duration_ms=duration_ms,
                    items_in=items_in, items_out=items_out, attempt=attempt,
                )
                telem = NodeTelemetry(
                    node=node_name, started_at=started_at,
                    finished_at=datetime.now(UTC), duration_ms=duration_ms,
                    items_in=items_in, items_out=items_out,
                    attempt=attempt, degraded=False,
                ).model_dump(mode="json")
                result["telemetry"] = [telem]
                return result
            except Exception as exc:
                last_exc = exc
                duration_ms = int((time.monotonic() - start_mono) * 1000)
                # Retry only transient / transport errors.
                if attempt <= _NODE_RETRY_BUDGET and _is_retryable(exc):
                    log_event(
                        self.logger, f"{node_name}_retry",
                        run_id=state["run_id"], attempt=attempt, error=str(exc),
                    )
                    continue
                # Deterministic or budget-exhausted — degrade.
                log_event(
                    self.logger, f"{node_name}_failed",
                    run_id=state["run_id"], error=str(exc),
                )
                fb = fallback()
                telem = NodeTelemetry(
                    node=node_name, started_at=started_at,
                    finished_at=datetime.now(UTC), duration_ms=duration_ms,
                    items_in=items_in, items_out=0,
                    attempt=attempt, degraded=True, error=str(exc),
                ).model_dump(mode="json")
                fb["telemetry"] = [telem]
                fb["errors"] = [f"{node_name}_failed: {exc}"]
                fb["warnings"] = [f"{node_name} ran in degraded mode: {exc}"]
                return fb
        raise last_exc  # type: ignore[misc]

    @staticmethod
    def _count_items(node_name: str, result: dict) -> int:
        for key in ("search_results", "incidents", "vulnerabilities"):
            if key in result and isinstance(result[key], list):
                return len(result[key])
        # report_agent returns {"analysis": {...}} — count findings.
        if "analysis" in result and isinstance(result["analysis"], dict):
            return len(result["analysis"].get("key_findings", [])) or 1
        return 0

    # -- node implementations -----------------------------------------

    def _search_node(self, state: AgentState) -> dict:
        request = state["request"]
        log_event(self.logger, "run_started", run_id=state["run_id"], query=request.query)
        return self._timed_node(
            "search_agent", state,
            fn=lambda: {"search_results": self.search_agent.run(request)},
            fallback=lambda: {"search_results": []},
            items_in=0,
        )

    def _extraction_node(self, state: AgentState) -> dict:
        results = state["search_results"]
        return self._timed_node(
            "extraction_agent", state,
            fn=lambda: {"incidents": self.extraction_agent.run(results)},
            fallback=lambda: {"incidents": []},
            items_in=len(results),
        )

    def _postprocess_node(self, state: AgentState) -> dict:
        incidents = state["incidents"]
        query = state["request"].query
        return self._timed_node(
            "postprocess_agent", state,
            fn=lambda: {"incidents": self.postprocess_agent.run(incidents, query)},
            fallback=lambda: {"incidents": incidents},
            items_in=len(incidents),
        )

    def _enrichment_node(self, state: AgentState) -> dict:
        incidents = state["incidents"]
        return self._timed_node(
            "cve_enrichment_agent", state,
            fn=lambda: {"vulnerabilities": self.enrichment_agent.run(incidents)},
            fallback=lambda: {"vulnerabilities": []},
            items_in=len(incidents),
        )

    def _analysis_node(self, state: AgentState) -> dict:
        incidents = state["incidents"]
        vulns = state["vulnerabilities"]
        query = state["request"].query
        return self._timed_node(
            "report_agent", state,
            fn=lambda: {"analysis": self.report_agent.run(query, incidents, vulns)},
            fallback=lambda: {"analysis": {}},
            items_in=len(incidents) + len(vulns),
        )

    def _report_node(self, state: AgentState) -> dict:
        from app.reporting import build_report

        started_at = datetime.now(UTC)
        start_mono = time.monotonic()

        report = build_report(
            state["request"].query,
            state["incidents"],
            state["vulnerabilities"],
            len(state["search_results"]),
            str(state["analysis"].get("executive_summary", "")),
            [str(item) for item in state["analysis"].get("key_findings", [])],
            [str(item) for item in state["analysis"].get("recommendations", [])],
            telemetry=state.get("telemetry", []),
            warnings=state.get("warnings", []),
        )

        duration_ms = int((time.monotonic() - start_mono) * 1000)
        telem = NodeTelemetry(
            node="report_builder", started_at=started_at,
            finished_at=datetime.now(UTC), duration_ms=duration_ms,
            items_in=len(state["incidents"]) + len(state["vulnerabilities"]),
            items_out=1,
        ).model_dump(mode="json")

        # Append report_builder telemetry to JSON and markdown so they match.
        try:
            rb_telem = NodeTelemetry(**telem)
            report.pipeline_telemetry.append(rb_telem)
            # Append to markdown so JSON and markdown stay consistent.
            status = "degraded" if rb_telem.degraded else "ok"
            rb_line = (
                f"\n- **{rb_telem.node}**: {rb_telem.duration_ms}ms, "
                f"in={rb_telem.items_in} out={rb_telem.items_out}, "
                f"attempt={rb_telem.attempt}, status={status}"
            )
            report.markdown_summary += rb_line
        except Exception:
            pass

        log_event(self.logger, "run_completed", run_id=state["run_id"])
        return {"report": report}


orchestrator = ThreatIntelOrchestrator()
