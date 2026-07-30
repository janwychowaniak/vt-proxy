"""Error contract: SPEC §9 mapping, one envelope shape for everything non-2xx."""

import httpx
import pytest
from conftest import EICAR_MD5, load_fixture, make_client


def _vt_responding(status: int, json_body=None, headers=None, text=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if text is not None:
            return httpx.Response(status, text=text, headers=headers)
        return httpx.Response(status, json=json_body, headers=headers)

    return handler


def _score_eicar(client):
    return client.post("/v1/score/file", json={"artifact": EICAR_MD5})


def test_vt_auth_failure_is_502_not_401():
    with make_client(_vt_responding(401, load_fixture("error_401_wrong_key"))) as client:
        response = _score_eicar(client)
    assert response.status_code == 502  # D8: caller must not think THEY need auth
    error = response.json()["error"]
    assert error["code"] == "UPSTREAM_AUTH"
    assert error["upstream"] == {
        "status": 401,
        "code": "WrongCredentialsError",
        "message": "Wrong API key",
    }


def test_vt_quota_passes_through_with_retry_after():
    handler = _vt_responding(
        429,
        {"error": {"code": "QuotaExceededError", "message": "Quota exceeded"}},
        headers={"Retry-After": "30"},
    )
    with make_client(handler) as client:
        response = _score_eicar(client)
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "30"
    assert response.json()["error"]["code"] == "UPSTREAM_QUOTA"


def test_vt_5xx_maps_to_upstream_error():
    handler = _vt_responding(503, {"error": {"code": "TransientError", "message": "try later"}})
    with make_client(handler) as client:
        response = _score_eicar(client)
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "UPSTREAM_ERROR"


def test_vt_own_504_is_a_timeout():  # D9: one symptom, one code
    body = {"error": {"code": "DeadlineExceededError", "message": "deadline"}}
    handler = _vt_responding(504, body)
    with make_client(handler) as client:
        response = _score_eicar(client)
    assert response.status_code == 504
    error = response.json()["error"]
    assert error["code"] == "UPSTREAM_TIMEOUT"
    assert error["upstream"]["code"] == "DeadlineExceededError"  # who noticed: visible here


def test_unmapped_vt_status_maps_to_upstream_error():
    handler = _vt_responding(400, {"error": {"code": "BadRequestError", "message": "bad"}})
    with make_client(handler) as client:
        response = _score_eicar(client)
    assert response.status_code == 502
    error = response.json()["error"]
    assert error["code"] == "UPSTREAM_ERROR"
    assert error["upstream"]["status"] == 400


def test_unparseable_vt_error_body_has_no_upstream():
    with make_client(_vt_responding(503, text="<html>load balancer says no</html>")) as client:
        response = _score_eicar(client)
    error = response.json()["error"]
    assert error["code"] == "UPSTREAM_ERROR"
    assert "upstream" not in error


@pytest.mark.parametrize("exc", [httpx.ConnectError("boom"), httpx.ReadTimeout("slow")])
def test_transport_failures_are_504(exc):
    def failing_handler(request: httpx.Request) -> httpx.Response:
        raise exc

    with make_client(failing_handler) as client:
        response = _score_eicar(client)
    assert response.status_code == 504
    error = response.json()["error"]
    assert error["code"] == "UPSTREAM_TIMEOUT"
    assert "upstream" not in error  # no VT answer existed


def test_vt_200_breaking_minimal_contract_is_upstream_schema():
    handler = _vt_responding(200, {"data": {"id": "x", "type": "file", "attributes": {}}})
    with make_client(handler) as client:
        response = _score_eicar(client)
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "UPSTREAM_SCHEMA"
