import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.metadata import version as pkg_version

import httpx
from fastapi import FastAPI

from .ca import CAFileError, load_ca_file, union_context
from .config import Settings
from .errors import register_error_handlers
from .log import get_logger, setup_logging
from .routes import router
from .vt import VTClient


def _extra_ca(path: str | None) -> ssl.SSLContext | None:
    """The union context for CA_FILE, or None when it is unset or empty (SPEC §10).

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
    return union_context(pem)


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
    verify = _extra_ca(settings.ca_file)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.vt = VTClient(
            base_url=settings.vt_base_url,
            api_key=settings.vt_api_key,
            timeout=settings.vt_timeout,
            transport=transport,
            verify=verify,
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
    app.state.extra_ca = verify is not None
    register_error_handlers(app)
    app.include_router(router)
    return app
