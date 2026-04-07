from __future__ import annotations

import asyncio
import uuid

from fastapi import FastAPI, HTTPException

from app.config import settings
from app.logging_utils import configure_logging
from app.models import StatusResponse, SubmitRunResponse, SearchRequest, Report, RunStatus
from app.orchestrator import orchestrator
from app.store import run_store


configure_logging()
app = FastAPI(title=settings.app_name)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/search", response_model=SubmitRunResponse, status_code=202)
async def submit_search(request: SearchRequest) -> SubmitRunResponse:
    run_id = str(uuid.uuid4())
    await run_store.create(run_id, request)
    asyncio.create_task(_execute_run(run_id, request))
    return SubmitRunResponse(run_id=run_id, status=RunStatus.pending)


@app.get("/search/{run_id}/status", response_model=StatusResponse)
async def get_status(run_id: str) -> StatusResponse:
    state = await run_store.get(run_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return StatusResponse(
        run_id=run_id,
        status=state.status,
        error=state.error,
        updated_at=state.updated_at,
    )


@app.get("/search/{run_id}/report", response_model=Report)
async def get_report(run_id: str) -> Report:
    state = await run_store.get(run_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Run not found")
    if state.status != RunStatus.completed or state.report is None:
        raise HTTPException(status_code=409, detail=f"Run is not complete: {state.status}")
    return state.report


async def _execute_run(run_id: str, request: SearchRequest) -> None:
    await run_store.set_status(run_id, RunStatus.running)
    try:
        report = await orchestrator.run(request, run_id)
        await run_store.set_report(run_id, report)
    except Exception as exc:
        await run_store.set_status(run_id, RunStatus.failed, error=str(exc))
