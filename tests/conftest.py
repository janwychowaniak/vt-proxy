import json
import ssl
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
import trustme
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


# --- TLS upstreams on loopback (CA_FILE, X509_STRICT) ----------------------------

API_KEY = "test-key-never-printed"
NO_UPSTREAM = "https://vt.invalid/api/v3"  # for tests that make no lookup
# what the client takes from the environment: proxies, and its own default trust
CLIENT_ENV = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)


@pytest.fixture
def isolated_client_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in CLIENT_ENV:
        monkeypatch.delenv(name, raising=False)


class _UnknownToVT(BaseHTTPRequestHandler):
    """Answers every GET the way VT answers for an unknown IOC."""

    def do_GET(self) -> None:
        body = json.dumps({"error": {"code": "NotFoundError", "message": "not found"}}).encode()
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # keep the test output clean
        pass


@contextmanager
def upstream(leaf: trustme.LeafCert) -> Iterator[str]:
    """An HTTPS upstream on loopback presenting `leaf`; yields its base URL."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    leaf.configure_cert(context)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _UnknownToVT)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}/api/v3"
    finally:
        server.shutdown()
        server.server_close()


def leaf_from(ca: trustme.CA) -> trustme.LeafCert:
    return ca.issue_cert("127.0.0.1")


def proxy_for(
    base_url: str, ca_file: str | None = None, x509_strict: str | None = None
) -> TestClient:
    """The service as a deployment builds it: settings in, real transport."""
    settings = Settings(
        vt_api_key=API_KEY,
        vt_base_url=base_url,
        ca_file=ca_file,
        x509_strict=x509_strict,
        _env_file=None,
    )
    return TestClient(create_app(settings=settings), raise_server_exceptions=False)


def pem_file(path: Path, *blobs: trustme.Blob) -> str:
    path.write_bytes(b"".join(blob.bytes() for blob in blobs))
    return str(path)


def assert_reached(client: TestClient) -> None:
    response = client.post("/v1/score/file", json={"artifact": UNKNOWN_SHA256})
    assert response.status_code == 200
    assert response.json()["known"] is False  # the upstream's 404, mapped as always


def assert_refused(client: TestClient) -> str:
    """The lookup fails on the transport-error path; returns the error's message."""
    response = client.post("/v1/score/file", json={"artifact": UNKNOWN_SHA256})
    assert response.status_code == 504  # the transport-error path, as for any failed TLS
    error = response.json()["error"]
    assert error["code"] == "UPSTREAM_TIMEOUT"
    return error["message"]
