"""Live smoke tests against the real VT API (SPEC §12).

Quota-cheap and OFF by default; enable explicitly with:

    VT_LIVE_TESTS=1 uv run pytest tests/test_live_smoke.py

Requires a real VT_API_KEY in the environment (or .env). Never runs in CI.
"""

import asyncio
import os

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("VT_LIVE_TESTS") != "1", reason="live smoke disabled (set VT_LIVE_TESTS=1)"
)

EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


def _client():
    from vt_proxy.config import Settings
    from vt_proxy.vt import VTClient

    settings = Settings()
    return VTClient(settings.vt_base_url, settings.vt_api_key, settings.vt_timeout)


def _run(coro):
    return asyncio.run(coro)


def test_live_file_lookup():
    async def check():
        client = _client()
        try:
            status, body = await client.get_json(f"/files/{EICAR_MD5}")
        finally:
            await client.aclose()
        assert status == 200
        assert "malicious" in body["data"]["attributes"]["last_analysis_stats"]

    _run(check())


def test_live_search_with_window_and_order():
    async def check():
        client = _client()
        try:
            status, body = await client.get_json(
                "/intelligence/search",
                {
                    "query": 'name:"eicar.com" ls:2026-06-30+',
                    "limit": 3,
                    "order": "last_submission_date-",
                },
            )
        finally:
            await client.aclose()
        assert status == 200
        dates = [item["attributes"]["last_submission_date"] for item in body["data"]]
        assert dates == sorted(dates, reverse=True)

    _run(check())
