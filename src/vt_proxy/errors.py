from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .log import error_line, get_logger

# Error codes (SPEC §9)
VALIDATION_ERROR = "VALIDATION_ERROR"
INVALID_ARTIFACT = "INVALID_ARTIFACT"
UPSTREAM_AUTH = "UPSTREAM_AUTH"
UPSTREAM_QUOTA = "UPSTREAM_QUOTA"
UPSTREAM_ERROR = "UPSTREAM_ERROR"
UPSTREAM_TIMEOUT = "UPSTREAM_TIMEOUT"
UPSTREAM_SCHEMA = "UPSTREAM_SCHEMA"
NOT_FOUND = "NOT_FOUND"
METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
INTERNAL = "INTERNAL"


class AppError(Exception):
    """Carries everything needed to render the SPEC §9 error envelope."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        upstream: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.upstream = upstream
        self.headers = headers


def _envelope(code: str, message: str, upstream: dict[str, Any] | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if upstream is not None:
        error["upstream"] = upstream
    return {"error": error}


def _respond(
    status_code: int,
    code: str,
    message: str,
    upstream: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    error_line(status=status_code, code=code, message=message, upstream=upstream)
    return JSONResponse(
        status_code=status_code,
        content=_envelope(code, message, upstream),
        headers=headers,
    )


async def _app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    return _respond(exc.status_code, exc.code, exc.message, exc.upstream, exc.headers)


async def _validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    parts = []
    for err in exc.errors():
        loc = ".".join(str(piece) for piece in err["loc"] if piece != "body")
        parts.append(f"{loc or 'body'}: {err['msg']}")
    return _respond(422, VALIDATION_ERROR, "; ".join(parts))


async def _http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    if exc.status_code == 404:
        return _respond(404, NOT_FOUND, "unknown path")
    if exc.status_code == 405:
        return _respond(405, METHOD_NOT_ALLOWED, "method not allowed for this path")
    return _respond(exc.status_code, INTERNAL, str(exc.detail))


async def _unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    get_logger().exception("unhandled error", extra={"fields": {"path": request.url.path}})
    return _respond(500, INTERNAL, "internal error")


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_handler)
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(Exception, _unhandled_handler)
