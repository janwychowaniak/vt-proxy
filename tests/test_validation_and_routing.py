"""Input validation boundary (SPEC §9), JSON types (SPEC §5, §8, D14), routing behavior
(SPEC §3, D14), health (SPEC §4)."""

import pytest
from conftest import EICAR_MD5

SCORE = ("/v1/score/file", {"artifact": EICAR_MD5})  # every score endpoint takes ScoreRequest
SEARCH = ("/v1/search/name", {"name": "eicar.com"})
POST_PATHS = (
    "/v1/score",
    "/v1/score/file",
    "/v1/score/ip",
    "/v1/score/domain",
    "/v1/score/url",
    "/v1/search/name",
)
METHOD_NOT_ALLOWED = {
    "error": {"code": "METHOD_NOT_ALLOWED", "message": "method not allowed for this path"}
}


def _error_code(response) -> str:
    return response.json()["error"]["code"]


# --- shape failures -> VALIDATION_ERROR -----------------------------------


def test_unknown_body_field_rejected(client):
    response = client.post(
        "/v1/score/file",
        json={"artifact": EICAR_MD5, "positives_tresh": 5},  # typo
    )
    assert response.status_code == 422
    assert _error_code(response) == "VALIDATION_ERROR"


def test_empty_artifact_is_shape_failure(client):
    response = client.post("/v1/score/file", json={"artifact": ""})
    assert response.status_code == 422
    assert _error_code(response) == "VALIDATION_ERROR"


def test_search_limit_out_of_range(client):
    response = client.post("/v1/search/name", json={"name": "x.exe", "limit": 41})
    assert response.status_code == 422
    assert _error_code(response) == "VALIDATION_ERROR"


def test_negative_thresh_rejected(client):
    response = client.post("/v1/score/file", json={"artifact": EICAR_MD5, "positives_thresh": -1})
    assert response.status_code == 422
    assert _error_code(response) == "VALIDATION_ERROR"


# --- content failures -> INVALID_ARTIFACT ---------------------------------


def test_garbage_artifact_on_omni(client):
    response = client.post("/v1/score", json={"artifact": "not an ioc at all"})
    assert response.status_code == 422
    assert _error_code(response) == "INVALID_ARTIFACT"


def test_type_mismatch_for_typed_endpoint(client):
    response = client.post("/v1/score/file", json={"artifact": "8.8.8.8"})
    assert response.status_code == 422
    assert _error_code(response) == "INVALID_ARTIFACT"


def test_sha512_like_hash_rejected(client):  # D10
    response = client.post("/v1/score/file", json={"artifact": "a" * 128})
    assert response.status_code == 422
    assert _error_code(response) == "INVALID_ARTIFACT"


def test_email_is_unsupported_on_omni(client):
    response = client.post("/v1/score", json={"artifact": "user@example.com"})
    assert response.status_code == 422
    assert _error_code(response) == "INVALID_ARTIFACT"


# --- JSON types, never coerced (SPEC §5, §8, D14) -------------------------

INTEGER_FIELDS = [
    (*SCORE, "positives_thresh", 5),
    (*SEARCH, "days_ago", 30),
    (*SEARCH, "limit", 10),
]
STRING_FIELDS = [
    (*SCORE, "artifact"),
    (*SCORE, "msg"),
    (*SEARCH, "name"),
    (*SEARCH, "msg"),
]


def _assert_shape_failure(response, field: str) -> None:
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert error["message"].startswith(f"{field}:")


# false on days_ago and limit is refused by the range (>= 1) as well, coerced or not;
# false on positives_thresh is the case only strict types refuse.
@pytest.mark.parametrize("value", ["5", 5.0, True, False])
@pytest.mark.parametrize(("path", "body", "field", "integer"), INTEGER_FIELDS)
def test_integer_field_refuses_other_json_types(client, path, body, field, integer, value):
    _assert_shape_failure(client.post(path, json={**body, field: value}), field)


@pytest.mark.parametrize(("path", "body", "field", "integer"), INTEGER_FIELDS)
def test_integer_field_takes_an_integer(client, path, body, field, integer):
    response = client.post(path, json={**body, field: integer})
    assert response.status_code == 200
    assert response.json()["query"][field] == integer


@pytest.mark.parametrize("value", [5, True])
@pytest.mark.parametrize(("path", "body", "field"), STRING_FIELDS)
def test_string_field_refuses_numbers_and_booleans(client, path, body, field, value):
    _assert_shape_failure(client.post(path, json={**body, field: value}), field)


# --- routing (SPEC §3) ----------------------------------------------------


def test_trailing_slash_is_enveloped_404(client):
    response = client.post("/v1/score/file/", json={"artifact": EICAR_MD5})
    assert response.status_code == 404
    assert _error_code(response) == "NOT_FOUND"


def test_unknown_path_is_enveloped_404(client):
    response = client.post("/v1/nonsense", json={})
    assert response.status_code == 404
    assert _error_code(response) == "NOT_FOUND"


def test_wrong_method_is_enveloped_405(client):
    response = client.get("/v1/score/file")
    assert response.status_code == 405
    assert _error_code(response) == "METHOD_NOT_ALLOWED"


@pytest.mark.parametrize(
    ("method", "path", "allow"),
    [("GET", path, "POST") for path in POST_PATHS]
    + [("HEAD", path, "POST") for path in POST_PATHS]
    + [("POST", "/v1/health", "GET"), ("HEAD", "/v1/health", "GET")],
)
def test_wrong_method_keeps_allow(client, method, path, allow):  # RFC 9110 §15.5.6, D14
    response = client.request(method, path)
    assert response.status_code == 405
    assert response.headers.get("allow") == allow
    if method == "HEAD":
        assert response.content == b""  # a HEAD answer has no body
    else:
        assert response.json() == METHOD_NOT_ALLOWED


# --- health (SPEC §4) -----------------------------------------------------


def test_health(client):
    response = client.get("/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["name"] == "vt-proxy"
    assert body["version"]
    assert body["extra_ca"] is False  # always present; true only with CA_FILE (test_ca_file.py)
