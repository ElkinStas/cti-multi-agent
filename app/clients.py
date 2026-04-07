from __future__ import annotations

import random
import time
import urllib.parse
from typing import Any

import httpx

from app.config import settings
from app.logging_utils import get_logger, log_event

logger = get_logger("http_client")

_MAX_RETRIES = 3
_BACKOFF_BASE_S = 0.5
_BACKOFF_MAX_S = 8.0
_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


def _backoff_delay(attempt: int) -> float:
    """Exponential backoff with jitter."""
    delay = min(_BACKOFF_BASE_S * (2 ** (attempt - 1)), _BACKOFF_MAX_S)
    return delay + random.uniform(0, delay * 0.5)


class HttpClient:
    """Thin wrapper around ``httpx.Client`` with retry, backoff, and jitter
    for transient errors (429 / 5xx / timeouts / connection failures)."""

    def __init__(self) -> None:
        self._client = httpx.Client(
            timeout=settings.request_timeout_seconds,
            headers={"User-Agent": settings.user_agent},
            follow_redirects=True,
        )

    def get_text(self, url: str, headers: dict[str, str] | None = None) -> str:
        return self._request("GET", url, headers=headers).text

    def get_text_with_url(
        self, url: str, headers: dict[str, str] | None = None
    ) -> tuple[str, str]:
        response = self._request("GET", url, headers=headers)
        return response.text, str(response.url)

    def get_json(
        self, url: str, headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        return self._request("GET", url, headers=headers).json()

    def post_json(
        self, url: str, payload: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        return self._request("POST", url, headers=headers, json=payload).json()

    @staticmethod
    def quote(value: str) -> str:
        return urllib.parse.quote(value)

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                response = self._client.request(method, url, **kwargs)
                if response.status_code in _RETRYABLE_STATUS_CODES and attempt < _MAX_RETRIES:
                    log_event(
                        logger, "http_retry",
                        url=url, status=response.status_code, attempt=attempt,
                    )
                    time.sleep(_backoff_delay(attempt))
                    continue
                response.raise_for_status()
                return response
            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    log_event(
                        logger, "http_retry",
                        url=url, error=type(exc).__name__, attempt=attempt,
                    )
                    time.sleep(_backoff_delay(attempt))
                    continue
                raise
            except httpx.HTTPStatusError:
                raise
        raise last_exc  # type: ignore[misc]


http_client = HttpClient()
