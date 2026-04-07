from __future__ import annotations

import hashlib
import time
import threading
from typing import Any


class SimpleCache:
    """Thread-safe in-memory cache with per-key TTL.

    Not durable across process restarts.  Production would replace this
    with Redis or another external cache; the interface is intentionally
    narrow so the swap is trivial.
    """

    def __init__(self) -> None:
        self._store: dict[str, tuple[Any, float]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: Any, ttl_s: int = 3600) -> None:
        with self._lock:
            self._store[key] = (value, time.monotonic() + ttl_s)

    def has(self, key: str) -> bool:
        return self.get(key) is not None


def prompt_cache_key(system: str, user: str, model: str) -> str:
    """Deterministic cache key for an LLM prompt."""
    raw = f"{model}::{system}::{user}"
    return f"llm:{hashlib.sha256(raw.encode()).hexdigest()}"


# Module-level singletons.
nvd_cache = SimpleCache()
llm_cache = SimpleCache()
