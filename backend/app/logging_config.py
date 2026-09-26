"""Structured JSON logging with per-request trace IDs.

Usage:
    from .logging_config import get_logger, setup_logging

    setup_logging(level="INFO")
    logger = get_logger(__name__)
    logger.info("scan completed", extra={"run_id": run.id, "count": 42})
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from contextvars import ContextVar
from typing import Any

# Per-request trace ID stored in a context variable so it is thread- and
# async-safe. The middleware sets it at the start of every request.
_trace_id: ContextVar[str] = ContextVar("trace_id", default="-")


def current_trace_id() -> str:
    return _trace_id.get()


def set_trace_id(value: str) -> None:
    _trace_id.set(value)


class _JsonFormatter(logging.Formatter):
    """Emit one JSON object per log record, suitable for log aggregators."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "trace_id": current_trace_id(),
            "msg": record.getMessage(),
        }
        # Forward any extra keys attached via logger.info("msg", extra={...})
        _skip = logging.LogRecord.__dict__.keys() | {
            "message",
            "asctime",
            "args",
            "exc_info",
            "exc_text",
            "stack_info",
            "taskName",
        }
        for key, value in record.__dict__.items():
            if key not in _skip and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(level: str = "INFO") -> None:
    """Configure root logger to emit JSON. Call once at application startup."""
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # Replace existing handlers to avoid duplicate output in reloading servers.
    root.handlers = [handler]
    # Quiet noisy third-party libraries.
    for name in ("uvicorn.access", "sqlalchemy.engine"):
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
