import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_LOGGER_NAME = "vt_proxy"


class JsonLineFormatter(logging.Formatter):
    """One JSON object per line (SPEC §11, D11)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if fields:
            payload.update(fields)
        if record.exc_info and record.exc_info[0] is not None:
            payload["exc_type"] = record.exc_info[0].__name__
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLineFormatter())
    logger = logging.getLogger(_LOGGER_NAME)
    logger.handlers = [handler]
    logger.setLevel(level.upper())
    logger.propagate = False
    # httpx logs request lines at INFO, including URLs; keep it quiet so no
    # header/URL detail ever reaches the log stream (SPEC §11: key hygiene).
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_logger() -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME)


def request_line(**fields: Any) -> None:
    """The per-request line for lookup/search endpoints (SPEC §11)."""
    get_logger().info("request", extra={"fields": fields})


def error_line(**fields: Any) -> None:
    get_logger().warning("error", extra={"fields": fields})
