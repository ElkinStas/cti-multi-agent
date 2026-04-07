from __future__ import annotations

import json

from app.cache import llm_cache, prompt_cache_key
from app.clients import http_client
from app.config import settings
from app.logging_utils import get_logger, log_event

logger = get_logger("llm")

# Lazy import — anthropic is optional; the system falls back to Ollama
# or heuristics when the package is not installed.
try:
    from anthropic import Anthropic
except ModuleNotFoundError:
    Anthropic = None  # type: ignore[assignment,misc]


def generate_json(
    system_prompt: str,
    user_prompt: str,
    *,
    model: str | None = None,
) -> dict | None:
    """Call the configured LLM and return parsed JSON, or ``None``.

    Results are cached by prompt hash so identical calls across articles
    or repeat runs avoid redundant LLM spend.
    """
    effective_model = model or settings.anthropic_extraction_model

    # -- cache lookup --------------------------------------------------
    cache_key = prompt_cache_key(system_prompt, user_prompt, effective_model)
    cached = llm_cache.get(cache_key)
    if cached is not None:
        log_event(logger, "llm_cache_hit", model=effective_model)
        return cached

    result = _call_anthropic(system_prompt, user_prompt, effective_model)
    if result is None:
        result = _call_ollama(system_prompt, user_prompt)
    if result is not None:
        llm_cache.set(cache_key, result, ttl_s=3600)
    return result


def _call_anthropic(
    system_prompt: str, user_prompt: str, model: str
) -> dict | None:
    if not settings.anthropic_api_key or Anthropic is None:
        return None
    try:
        client = Anthropic(
            api_key=settings.anthropic_api_key,
            base_url=settings.anthropic_base_url,
            timeout=settings.request_timeout_seconds,
        )
        response = client.messages.create(
            model=model,
            max_tokens=1500,
            system=f"{system_prompt} Return valid JSON only.",
            messages=[{"role": "user", "content": user_prompt}],
        )
        content = "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )
        log_event(logger, "llm_call", provider="anthropic", model=model)
        return json.loads(content)
    except Exception as exc:
        log_event(
            logger, "llm_call_failed",
            provider="anthropic", model=model, error=type(exc).__name__, detail=str(exc)[:200],
        )
        return None


def _call_ollama(system_prompt: str, user_prompt: str) -> dict | None:
    if not settings.ollama_model:
        return None
    try:
        response = http_client.post_json(
            f"{settings.ollama_base_url.rstrip('/')}/api/generate",
            {
                "model": settings.ollama_model,
                "prompt": f"{system_prompt}\n\n{user_prompt}\n\nReturn valid JSON only.",
                "stream": False,
                "format": "json",
            },
        )
        generated = response.get("response")
        if not isinstance(generated, str):
            return None
        log_event(logger, "llm_call", provider="ollama", model=settings.ollama_model)
        return json.loads(generated)
    except Exception as exc:
        log_event(
            logger, "llm_call_failed",
            provider="ollama", model=settings.ollama_model, error=type(exc).__name__, detail=str(exc)[:200],
        )
        return None
