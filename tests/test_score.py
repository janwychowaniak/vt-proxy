"""Score endpoints against captured fixtures (SPEC §5-§7)."""

from conftest import EICAR_MD5, EICAR_SHA256, EXAMPLE_URL, UNKNOWN_SHA256


def test_known_file_envelope(client):
    response = client.post(
        "/v1/score/file",
        json={"artifact": EICAR_MD5, "positives_thresh": 5, "msg": "case-4711"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["query"] == {
        "artifact": EICAR_MD5,  # echoed verbatim, not normalized
        "type": "file",
        "positives_thresh": 5,
        "msg": "case-4711",
    }
    assert body["known"] is True
    assert body["verdict"]["score"] == 65
    assert body["verdict"]["thresh_gte"] is True
    assert body["verdict"]["stats"]["type-unsupported"] == 6  # kebab-case keys intact
    assert body["report"]["id"] == EICAR_SHA256  # VT normalized md5 -> sha256
    assert body["report"]["type"] == "file"
    assert body["report"]["attributes"]["last_analysis_stats"] == body["verdict"]["stats"]


def test_unknown_file_is_success_not_error(client):
    response = client.post("/v1/score/file", json={"artifact": UNKNOWN_SHA256})
    assert response.status_code == 200
    body = response.json()
    assert body["known"] is False
    assert body["verdict"] is None
    assert body["report"] is None
    assert body["query"]["positives_thresh"] == 1  # D4 default echoed


def test_thresh_gte_is_inclusive(client):
    at_threshold = client.post(
        "/v1/score/file", json={"artifact": EICAR_MD5, "positives_thresh": 65}
    ).json()
    above_threshold = client.post(
        "/v1/score/file", json={"artifact": EICAR_MD5, "positives_thresh": 66}
    ).json()
    assert at_threshold["verdict"]["thresh_gte"] is True
    assert above_threshold["verdict"]["thresh_gte"] is False


def test_ip_score(client):
    body = client.post("/v1/score/ip", json={"artifact": "8.8.8.8"}).json()
    assert body["known"] is True
    assert body["verdict"]["score"] == 0
    assert body["verdict"]["thresh_gte"] is False
    assert body["report"]["type"] == "ip_address"  # VT vocabulary, never renamed
    assert body["query"]["type"] == "ip"  # our vocabulary, deliberately different


def test_ipv6_score(client):
    body = client.post("/v1/score/ip", json={"artifact": "2001:4860:4860::8888"}).json()
    assert body["known"] is True
    assert body["report"]["id"] == "2001:4860:4860::8888"


def test_domain_score(client):
    body = client.post("/v1/score/domain", json={"artifact": "example.com"}).json()
    assert body["known"] is True
    assert body["report"]["id"] == "example.com"


def test_url_score_uses_base64url_id(client):
    body = client.post("/v1/score/url", json={"artifact": EXAMPLE_URL}).json()
    assert body["known"] is True
    assert body["report"]["attributes"]["url"] == EXAMPLE_URL
    assert body["query"]["artifact"] == EXAMPLE_URL


def test_omni_dispatches_by_detected_type(client):
    for artifact, expected_type in [
        (EICAR_MD5, "file"),
        ("8.8.8.8", "ip"),
        ("example.com", "domain"),
        (EXAMPLE_URL, "url"),
    ]:
        body = client.post("/v1/score", json={"artifact": artifact}).json()
        assert body["query"]["type"] == expected_type, artifact
        assert body["known"] is True, artifact
