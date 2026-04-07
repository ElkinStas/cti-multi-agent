from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ModuleNotFoundError:
    pass


@dataclass(frozen=True)
class Settings:
    app_name: str = "Cyber Threat Intelligence Agent System"
    default_max_articles: int = int(os.getenv("DEFAULT_MAX_ARTICLES", "5"))
    anthropic_api_key: str | None = os.getenv("ANTHROPIC_API_KEY") or None
    anthropic_extraction_model: str = os.getenv(
        "ANTHROPIC_EXTRACTION_MODEL", "claude-haiku-4-20250414"
    )
    anthropic_report_model: str = os.getenv(
        "ANTHROPIC_REPORT_MODEL", "claude-sonnet-4-20250514"
    )
    anthropic_base_url: str | None = os.getenv("ANTHROPIC_BASE_URL") or None
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    ollama_model: str | None = os.getenv("OLLAMA_MODEL") or None
    request_timeout_seconds: float = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "20"))
    max_llm_chars_per_article: int = int(os.getenv("MAX_LLM_CHARS_PER_ARTICLE", "8000"))
    user_agent: str = os.getenv(
        "USER_AGENT",
        "cyber-threat-intel-agent/0.1 (+https://example.local)",
    )


settings = Settings()
