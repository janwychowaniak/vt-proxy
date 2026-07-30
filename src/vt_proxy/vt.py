import base64
from typing import Any

import httpx

from .errors import (
    UPSTREAM_AUTH,
    UPSTREAM_ERROR,
    UPSTREAM_QUOTA,
    UPSTREAM_SCHEMA,
    UPSTREAM_TIMEOUT,
    AppError,
)


def url_id(url: str) -> str:
    """VT v3 URL identifier: base64url without padding (SPEC §4, NOTES §4)."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _parse_upstream(response: httpx.Response) -> dict[str, Any] | None:
    """VT's error object, if the body parses as one; otherwise None (SPEC §9)."""
    try:
        body = response.json()
        error = body["error"]
        return {
            "status": response.status_code,
            "code": error["code"],
            "message": error["message"],
        }
    except (ValueError, KeyError, TypeError):
        return None


def _map_error(response: httpx.Response) -> AppError:
    """Map a non-200, non-404 VT response to our error contract (SPEC §9)."""
    status = response.status_code
    upstream = _parse_upstream(response)
    if status in (401, 403):
        return AppError(502, UPSTREAM_AUTH, "VT rejected this service's credentials", upstream)
    if status == 429:
        headers = None
        retry_after = response.headers.get("Retry-After")
        if retry_after is not None:
            headers = {"Retry-After": retry_after}
        return AppError(429, UPSTREAM_QUOTA, "VT quota or rate limit exceeded", upstream, headers)
    if status == 504:  # D9: VT's own deadline counts as a timeout
        return AppError(504, UPSTREAM_TIMEOUT, "VT reported a timeout", upstream)
    return AppError(502, UPSTREAM_ERROR, f"VT answered HTTP {status}", upstream)


class VTClient:
    """Thin async wrapper over the VT v3 endpoints this service uses.

    Read-only by construction: only GET requests exist here. The underlying
    httpx client keeps trust_env enabled so standard proxy variables work
    (SPEC §10).
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"x-apikey": api_key},
            timeout=timeout,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        try:
            return await self._client.get(path, params=params)
        except httpx.TransportError as exc:
            raise AppError(
                504, UPSTREAM_TIMEOUT, f"VT unreachable or timed out ({type(exc).__name__})"
            ) from exc

    async def get_json(
        self, path: str, params: dict[str, Any] | None = None
    ) -> tuple[int, dict[str, Any] | None]:
        """GET a VT path.

        Returns (status, parsed body) for 200, (404, None) for VT's
        NotFoundError — which is not an error here (SPEC §9) — and raises
        AppError for everything else.
        """
        response = await self._get(path, params)
        if response.status_code == 200:
            try:
                return 200, response.json()
            except ValueError as exc:
                raise AppError(
                    502, UPSTREAM_SCHEMA, "VT answered 200 with a non-JSON body"
                ) from exc
        if response.status_code == 404:
            return 404, None
        raise _map_error(response)
