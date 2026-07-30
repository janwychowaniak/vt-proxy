from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import ValidationError

from .errors import INVALID_ARTIFACT, UPSTREAM_SCHEMA, AppError
from .schemas import validate_vt_object
from .vt import VTClient

# The name is embedded into a VT query string; a double quote could smuggle
# extra search modifiers in (SPEC §8 query-injection guard).
_FORBIDDEN_IN_NAME = '"'

_PROJECTED_ATTRS = ("sha256", "sha1", "md5", "size", "type_description", "meaningful_name")


def _iso_utc(epoch: Any) -> str | None:
    if epoch is None:
        return None
    stamp = datetime.fromtimestamp(int(epoch), tz=UTC).isoformat(timespec="seconds")
    return stamp.replace("+00:00", "Z")


def _project(item: dict[str, Any]) -> dict[str, Any]:
    """SPEC §8 trimmed projection of one VT file object. Nullable except score/stats."""
    try:
        validate_vt_object(item)
    except ValidationError as exc:
        raise AppError(
            502, UPSTREAM_SCHEMA, "a search result item fails the minimal contract"
        ) from exc

    attributes = item["attributes"]
    stats: dict[str, int] = attributes["last_analysis_stats"]
    projection: dict[str, Any] = {attr: attributes.get(attr) for attr in _PROJECTED_ATTRS}
    if projection["sha256"] is None:
        projection["sha256"] = item["id"]  # identical for file objects (NOTES §4)
    projection["first_submission_date"] = _iso_utc(attributes.get("first_submission_date"))
    projection["last_submission_date"] = _iso_utc(attributes.get("last_submission_date"))
    projection["score"] = stats["malicious"]
    projection["stats"] = stats
    return projection


async def search_by_name(
    client: VTClient,
    name: str,
    days_ago: int,
    limit: int,
    msg: str | None,
) -> tuple[dict[str, Any], int]:
    """Name->hash lookup via VT Intelligence search (SPEC §8). Returns (envelope, vt_status)."""
    if _FORBIDDEN_IN_NAME in name:
        raise AppError(422, INVALID_ARTIFACT, "name must not contain double quotes")

    since = (datetime.now(UTC).date() - timedelta(days=days_ago)).isoformat()
    params = {
        "query": f'name:"{name}" ls:{since}+',
        "limit": limit,
        "order": "last_submission_date-",  # newest first, server-side (verified live)
    }
    vt_status, body = await client.get_json("/intelligence/search", params)

    if body is None:  # a hypothetical VT 404: empty success, never an error (SPEC §9)
        matches: list[dict[str, Any]] = []
        total_hits = 0
    else:
        items = body.get("data")
        if not isinstance(items, list):
            raise AppError(502, UPSTREAM_SCHEMA, "search response lacks a data list")
        matches = [_project(item) for item in items]
        meta = body.get("meta") or {}
        total_hits = meta.get("total_hits", len(matches))

    envelope = {
        "query": {"name": name, "days_ago": days_ago, "limit": limit, "msg": msg},
        "known": len(matches) > 0,
        "total_hits": total_hits,
        "matches": matches,
    }
    return envelope, vt_status
