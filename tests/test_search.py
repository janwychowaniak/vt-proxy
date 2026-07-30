"""Name->hash search endpoint (SPEC §8)."""

import httpx
from conftest import make_client


def test_search_projection_from_fixture(client):
    response = client.post("/v1/search/name", json={"name": "eicar.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["query"] == {"name": "eicar.com", "days_ago": 30, "limit": 10, "msg": None}
    assert body["known"] is True
    assert body["total_hits"] == 166  # meta.total_hits passthrough

    first = body["matches"][0]
    assert first == {
        "sha256": "f4041df12ec3d79722af2cf64a1dbce9de928b773c61e11aaa9359e7fdbb6ac0",
        "sha1": "9f45ae3ae43708d07f7af586d5e411256b7716aa",
        "md5": "6a9f6c15ac2b8f80a60c0103539c9ebd",
        "size": 127,
        "type_description": "Powershell",
        "meaningful_name": "CEPlus.sh",
        "first_submission_date": "2026-04-30T12:08:51Z",  # epoch converted to ISO UTC
        "last_submission_date": "2026-07-29T13:24:02Z",
        "score": 56,
        "stats": first["stats"],
    }
    assert first["stats"]["malicious"] == 56
    assert len(body["matches"]) == 5


def test_search_sends_window_order_and_limit():
    seen: dict = {}

    def recording_handler(request: httpx.Request) -> httpx.Response:
        seen["params"] = dict(request.url.params)
        return httpx.Response(200, json={"data": [], "meta": {"total_hits": 0}})

    with make_client(recording_handler) as client:
        client.post("/v1/search/name", json={"name": "faktura.exe", "days_ago": 7, "limit": 3})

    assert seen["params"]["limit"] == "3"
    assert seen["params"]["order"] == "last_submission_date-"
    query = seen["params"]["query"]
    assert query.startswith('name:"faktura.exe" ls:')
    assert query.endswith("+")


def test_search_zero_matches_is_success():
    def empty_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [], "meta": {"total_hits": 0}})

    with make_client(empty_handler) as client:
        body = client.post("/v1/search/name", json={"name": "nosuchname.xyz"}).json()
    assert body == {
        "query": {"name": "nosuchname.xyz", "days_ago": 30, "limit": 10, "msg": None},
        "known": False,
        "total_hits": 0,
        "matches": [],
    }


def test_search_projection_fields_nullable():
    item = {
        "id": "aa" * 32,
        "type": "file",
        "attributes": {"last_analysis_stats": {"malicious": 3}},
    }

    def sparse_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [item], "meta": {"total_hits": 1}})

    with make_client(sparse_handler) as client:
        body = client.post("/v1/search/name", json={"name": "sparse.bin"}).json()
    match = body["matches"][0]
    assert match["sha256"] == "aa" * 32  # falls back to data.id
    assert match["md5"] is None
    assert match["meaningful_name"] is None
    assert match["first_submission_date"] is None
    assert match["score"] == 3


def test_search_quote_in_name_rejected_before_vt(client):
    response = client.post("/v1/search/name", json={"name": 'evil" p:0+ x:"'})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_ARTIFACT"


def test_search_bad_item_fails_whole_request():
    def broken_handler(request: httpx.Request) -> httpx.Response:
        good = {
            "id": "bb" * 32,
            "type": "file",
            "attributes": {"last_analysis_stats": {"malicious": 0}},
        }
        broken = {"id": "cc" * 32, "type": "file", "attributes": {}}
        return httpx.Response(200, json={"data": [good, broken], "meta": {"total_hits": 2}})

    with make_client(broken_handler) as client:
        response = client.post("/v1/search/name", json={"name": "whatever.exe"})
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "UPSTREAM_SCHEMA"
