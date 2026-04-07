from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    payload = {
        "ts": datetime.now(UTC).isoformat(),
        "logger": logger.name,
        "event": event,
        **fields,
    }
    logger.info(json.dumps(payload, default=str))
