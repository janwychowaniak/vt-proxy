from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.metadata import version as pkg_version

import httpx
from fastapi import FastAPI

from .config import Settings
from .errors import register_error_handlers
from .log import setup_logging
from .routes import router
from .vt import VTClient


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

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.vt = VTClient(
            base_url=settings.vt_base_url,
            api_key=settings.vt_api_key,
            timeout=settings.vt_timeout,
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
    register_error_handlers(app)
    app.include_router(router)
    return app
