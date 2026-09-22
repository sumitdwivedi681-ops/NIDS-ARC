"""
Request Logging Middleware.

Logs every HTTP request with method, path, status, and duration.
Assigns a unique request_id to each request.
"""

from __future__ import annotations

import time
from uuid import uuid4

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


logger = structlog.get_logger("http")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log HTTP requests with timing and request ID."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = str(uuid4())
        request.state.request_id = request_id

        start_time = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "request_error",
                request_id=request_id,
                method=request.method,
                path=str(request.url.path),
                duration_ms=round(duration_ms, 2),
                error=str(exc),
            )
            raise

        duration_ms = (time.perf_counter() - start_time) * 1000
        response.headers["X-Request-ID"] = request_id

        logger.info(
            "request_completed",
            request_id=request_id,
            method=request.method,
            path=str(request.url.path),
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2),
        )

        return response
