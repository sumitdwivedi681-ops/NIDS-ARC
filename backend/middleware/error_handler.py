"""
Error Handling Middleware.

Catches exceptions and returns structured error responses.
Never exposes stack traces in production.
"""

from __future__ import annotations

import traceback

import structlog
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from backend.config import get_settings

logger = structlog.get_logger("error_handler")


class AppError(Exception):
    """Base application error."""
    def __init__(self, message: str, code: str = "INTERNAL_ERROR", status_code: int = 500, details: list = None):
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or []
        super().__init__(message)


class ValidationError(AppError):
    def __init__(self, message: str = "Validation failed", details: list = None):
        super().__init__(message, "VALIDATION_ERROR", 400, details)


class AuthenticationError(AppError):
    def __init__(self, message: str = "Authentication required"):
        super().__init__(message, "AUTHENTICATION_ERROR", 401)


class AuthorizationError(AppError):
    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(message, "AUTHORIZATION_ERROR", 403)


class NotFoundError(AppError):
    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, "NOT_FOUND", 404)


class ConflictError(AppError):
    def __init__(self, message: str = "Resource conflict"):
        super().__init__(message, "CONFLICT", 409)


class RateLimitError(AppError):
    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(message, "RATE_LIMIT_EXCEEDED", 429)


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """Catch unhandled exceptions and return structured JSON errors."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            return await call_next(request)
        except AppError as exc:
            return self._error_response(request, exc.status_code, exc.code, exc.message, exc.details)
        except Exception as exc:
            settings = get_settings()
            logger.error(
                "unhandled_exception",
                error=str(exc),
                path=str(request.url.path),
                traceback=traceback.format_exc() if settings.app_debug else None,
            )
            message = str(exc) if settings.app_debug else "An internal error occurred"
            return self._error_response(request, 500, "INTERNAL_ERROR", message)

    def _error_response(
        self,
        request: Request,
        status_code: int,
        code: str,
        message: str,
        details: list = None,
    ) -> JSONResponse:
        from datetime import datetime, timezone

        request_id = getattr(request.state, "request_id", "unknown")
        return JSONResponse(
            status_code=status_code,
            content={
                "error": {
                    "code": code,
                    "message": message,
                    "details": [{"message": d} if isinstance(d, str) else d for d in (details or [])],
                },
                "meta": {
                    "request_id": request_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            },
        )
