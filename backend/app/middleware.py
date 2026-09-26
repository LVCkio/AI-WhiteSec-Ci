"""FastAPI middleware collection.

Included middleware (applied in order):
1. TraceMiddleware  — injects a unique X-Trace-ID into every request/response
                     and emits a structured access log entry.
2. APIKeyMiddleware — enforces X-API-Key header on all /api/* routes when
                     API_KEY is configured in .env.  Public routes (/health,
                     /, /static/*, /docs, /openapi.json) are always exempt.
"""
from __future__ import annotations

import secrets
import time
import uuid

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from .config import get_settings
from .logging_config import get_logger, set_trace_id

logger = get_logger(__name__)

# Routes that never require an API key.
_PUBLIC_PREFIXES = (
    "/health",
    "/static",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
)


class TraceMiddleware(BaseHTTPMiddleware):
    """Attach a unique trace ID to every request and emit a structured log."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        trace_id = request.headers.get("X-Trace-ID") or str(uuid.uuid4())
        set_trace_id(trace_id)
        started = time.perf_counter()
        response: Response = await call_next(request)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        response.headers["X-Trace-ID"] = trace_id
        logger.info(
            "request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": elapsed_ms,
            },
        )
        return response


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Reject requests to /api/* that lack a valid X-API-Key header.

    Authentication is disabled when ``settings.api_key`` is empty (default for
    local development).  Set ``API_KEY=<secret>`` in .env to enable it.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()

        # Auth is disabled — pass everything through.
        if not settings.auth_enabled:
            return await call_next(request)

        path = request.url.path

        # Public routes are always exempt.
        if path == "/" or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        # Only gate API routes.
        if path.startswith("/api/"):
            provided_key = request.headers.get("X-API-Key", "")
            if not provided_key or not secrets.compare_digest(
                provided_key.encode(), settings.api_key.encode()
            ):
                logger.warning(
                    "unauthorized",
                    extra={"path": path, "method": request.method},
                )
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Missing or invalid X-API-Key header."},
                    headers={"X-Trace-ID": str(uuid.uuid4())},
                )

        return await call_next(request)
