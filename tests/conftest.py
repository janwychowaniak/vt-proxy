import json
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from vt_proxy.config import Settings
from vt_proxy.main import create_app

FIXTURES = Path(__file__).resolve().parent.parent / "docs" / "research" / "fixtures"

EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
UNKNOWN_SHA256 = "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0"
EXAMPLE_URL = "http://example.com/"
EXAMPLE_URL_ID = "aHR0cDovL2V4YW1wbGUuY29tLw"  # base64url of the above, no padding


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def default_vt_handler(request: httpx.Request) -> httpx.Response:
    """Serves captured fixtures for the canonical happy/unknown paths."""
    routes = {
        f"/files/{EICAR_MD5}": ("file_eicar_by_md5", 200),
        f"/files/{UNKNOWN_SHA256}": ("file_unknown_404", 404),
        "/ip_addresses/8.8.8.8": ("ip_google_dns", 200),
        "/ip_addresses/2001:4860:4860::8888": ("ip6_google_dns", 200),
        "/domains/example.com": ("domain_example_com", 200),
        f"/urls/{EXAMPLE_URL_ID}": ("url_example_com", 200),
        "/intelligence/search": ("intel_search_eicar_by_name", 200),
    }
    if request.url.path in routes:
        name, status = routes[request.url.path]
        return httpx.Response(status, json=load_fixture(name))
    return httpx.Response(
        404, json={"error": {"code": "NotFoundError", "message": "Resource not found."}}
    )


def make_client(
    handler: Callable[[httpx.Request], httpx.Response] = default_vt_handler,
) -> TestClient:
    settings = Settings(
        vt_api_key="test-key-not-real",
        vt_base_url="https://vt.mock",  # no path prefix: fixture routes match exactly
        _env_file=None,  # never read the developer's real .env in tests
    )
    app = create_app(settings=settings, transport=httpx.MockTransport(handler))
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with make_client() as test_client:
        yield test_client
