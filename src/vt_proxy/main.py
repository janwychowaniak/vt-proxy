from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.metadata import version as pkg_version

import httpx
from fastapi import FastAPI

from .ca import CAFileError, load_ca_file
from .config import Settings
from .errors import register_error_handlers
from .log import get_logger, setup_logging
from .routes import router
from .tls import X509StrictError, parse_x509_strict, upstream_context
from .vt import VTClient


def _x509_strict(value: str | None) -> bool:
    """X509_STRICT as a boolean; unset or empty means true (SPEC §10).

    A value that is neither true nor false ends the process here, the way a CA_FILE
    that cannot be used does.
    """
    try:
        return parse_x509_strict(value)
    except X509StrictError as exc:
        raise SystemExit(str(exc)) from None


def _extra_ca(path: str | None) -> str | None:
    """The PEM text of CA_FILE, or None when it is unset or empty (SPEC §10).

    A file that cannot be used ends the process here: a SystemExit carrying the
    refusal line is all uvicorn prints, so that line is the last thing in the log.
    """
    if not path:
        return None
    try:
        pem, count = load_ca_file(path)
    except CAFileError as exc:
        raise SystemExit(str(exc)) from None
    get_logger().info("ca_file_loaded", extra={"fields": {"path": path, "certificates": count}})
    return pem


def create_app(
    settings: Settings | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """App factory. Run with: uvicorn --factory vt_proxy.main:create_app

    `settings`/`transport` overrides exist for tests (SPEC §12); production
    uses environment-driven Settings and httpx's real transport (with
    trust_env proxy support, SPEC §10).
    """
    settings = settings or Settings()
    setup_logging(settings.log_level)
    strict = _x509_strict(settings.x509_strict)  # before CA_FILE is read
    pem = _extra_ca(settings.ca_file)
    context = upstream_context(pem, strict)
    if not strict:
        get_logger().warning("x509_strict_disabled")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.vt = VTClient(
            base_url=settings.vt_base_url,
            api_key=settings.vt_api_key,
            timeout=settings.vt_timeout,
            verify=context,
            transport=transport,
        )
        try:
            yield
        finally:
            await app.state.vt.aclose()

    app = FastAPI(
        title="vt-proxy",
        version=pkg_version("vt-proxy"),
        redirect_slashes=False,  # SPEC §3: a trailing-slash path is a 404, not a redirect
        lifespan=lifespan,
    )
    app.state.extra_ca = pem is not None
    app.state.tls = context  # health reads x509_strict from the context itself
    register_error_handlers(app)
    app.include_router(router)
    return app
