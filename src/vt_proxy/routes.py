import time
from importlib.metadata import version as pkg_version
from typing import Any

from fastapi import APIRouter, Request

from .errors import INVALID_ARTIFACT, AppError
from .ioc import DOMAIN, FILE, IP, URL, resolve_type
from .log import request_line
from .schemas import ScoreRequest, SearchRequest
from .score import score_artifact
from .search import search_by_name
from .vt import VTClient

router = APIRouter(prefix="/v1")


def _vt(request: Request) -> VTClient:
    return request.app.state.vt


async def _handle_score(
    request: Request, body: ScoreRequest, expected_type: str | None, endpoint: str
) -> dict[str, Any]:
    started = time.perf_counter()
    resolved = resolve_type(body.artifact)
    if expected_type is not None and resolved != expected_type:
        raise AppError(422, INVALID_ARTIFACT, f"artifact is not a valid {expected_type}")
    if resolved is None:  # omni: undetermined or unsupported (SPEC §7, D6)
        raise AppError(422, INVALID_ARTIFACT, "could not determine a supported IOC type")

    envelope, vt_status = await score_artifact(
        _vt(request), body.artifact, resolved, body.positives_thresh, body.msg
    )
    verdict = envelope["verdict"]
    request_line(
        endpoint=endpoint,
        type=resolved,
        artifact=body.artifact,
        known=envelope["known"],
        score=verdict["score"] if verdict else None,
        positives_thresh=body.positives_thresh,
        msg=body.msg,
        vt_status=vt_status,
        duration_ms=round((time.perf_counter() - started) * 1000),
    )
    return envelope


@router.post("/score/file")
async def score_file(request: Request, body: ScoreRequest) -> dict[str, Any]:
    return await _handle_score(request, body, FILE, "/v1/score/file")


@router.post("/score/ip")
async def score_ip(request: Request, body: ScoreRequest) -> dict[str, Any]:
    return await _handle_score(request, body, IP, "/v1/score/ip")


@router.post("/score/domain")
async def score_domain(request: Request, body: ScoreRequest) -> dict[str, Any]:
    return await _handle_score(request, body, DOMAIN, "/v1/score/domain")


@router.post("/score/url")
async def score_url(request: Request, body: ScoreRequest) -> dict[str, Any]:
    return await _handle_score(request, body, URL, "/v1/score/url")


@router.post("/score")
async def score_omni(request: Request, body: ScoreRequest) -> dict[str, Any]:
    return await _handle_score(request, body, None, "/v1/score")


@router.post("/search/name")
async def search_name(request: Request, body: SearchRequest) -> dict[str, Any]:
    started = time.perf_counter()
    envelope, vt_status = await search_by_name(
        _vt(request), body.name, body.days_ago, body.limit, body.msg
    )
    request_line(
        endpoint="/v1/search/name",
        type="search",
        artifact=body.name,
        known=envelope["known"],
        total_hits=envelope["total_hits"],
        msg=body.msg,
        vt_status=vt_status,
        duration_ms=round((time.perf_counter() - started) * 1000),
    )
    return envelope


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "name": "vt-proxy", "version": pkg_version("vt-proxy")}
