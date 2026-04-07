from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from app.models import Report, RunState, RunStatus, SearchRequest


class InMemoryRunStore:
    def __init__(self) -> None:
        self._runs: dict[str, RunState] = {}
        self._lock = asyncio.Lock()

    async def create(self, run_id: str, request: SearchRequest) -> RunState:
        async with self._lock:
            state = RunState(run_id=run_id, status=RunStatus.pending, request=request)
            self._runs[run_id] = state
            return state

    async def get(self, run_id: str) -> RunState | None:
        async with self._lock:
            return self._runs.get(run_id)

    async def set_status(self, run_id: str, status: RunStatus, error: str | None = None) -> None:
        async with self._lock:
            state = self._runs[run_id]
            state.status = status
            state.error = error
            state.updated_at = datetime.now(UTC)

    async def set_report(self, run_id: str, report: Report) -> None:
        async with self._lock:
            state = self._runs[run_id]
            state.status = RunStatus.completed
            state.report = report
            state.updated_at = datetime.now(UTC)


run_store = InMemoryRunStore()
