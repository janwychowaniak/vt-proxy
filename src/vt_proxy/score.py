from typing import Any

from pydantic import ValidationError

from .errors import UPSTREAM_SCHEMA, AppError
from .ioc import DOMAIN, FILE, IP, URL
from .schemas import validate_vt_object
from .vt import VTClient, url_id

_PATH_PREFIX = {FILE: "/files", IP: "/ip_addresses", DOMAIN: "/domains"}


def _vt_path(resolved_type: str, artifact: str) -> str:
    if resolved_type == URL:
        return f"/urls/{url_id(artifact)}"
    return f"{_PATH_PREFIX[resolved_type]}/{artifact}"


async def score_artifact(
    client: VTClient,
    artifact: str,
    resolved_type: str,
    positives_thresh: int,
    msg: str | None,
) -> tuple[dict[str, Any], int]:
    """One score lookup: VT call -> SPEC §6 envelope. Returns (envelope, vt_status)."""
    query = {
        "artifact": artifact,
        "type": resolved_type,
        "positives_thresh": positives_thresh,
        "msg": msg,
    }
    vt_status, body = await client.get_json(_vt_path(resolved_type, artifact))
    if body is None:  # VT 404: not an error — VT simply doesn't know it (SPEC §9)
        return {"query": query, "known": False, "verdict": None, "report": None}, vt_status

    data = body.get("data")
    try:
        validate_vt_object(data)
    except ValidationError as exc:
        raise AppError(502, UPSTREAM_SCHEMA, "VT response fails the minimal contract") from exc

    stats: dict[str, int] = data["attributes"]["last_analysis_stats"]
    score = stats["malicious"]
    envelope = {
        "query": query,
        "known": True,
        "verdict": {
            "score": score,
            "thresh_gte": score >= positives_thresh,
            "stats": stats,
        },
        "report": data,  # the VT v3 `data` object verbatim (SPEC §6)
    }
    return envelope, vt_status
