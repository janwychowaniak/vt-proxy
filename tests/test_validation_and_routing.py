"""Input validation boundary (SPEC §9), routing behavior (SPEC §3), health (SPEC §4)."""

from conftest import EICAR_MD5


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


# --- health (SPEC §4) -----------------------------------------------------


def test_health(client):
    response = client.get("/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["name"] == "vt-proxy"
    assert body["version"]
