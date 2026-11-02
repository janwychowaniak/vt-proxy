from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScoreRequest(BaseModel):
    """Uniform body of all five score endpoints (SPEC §5).

    Strict JSON types (D14): a field of another type is a shape failure, never
    coerced, so "5", 5.0 or true is not read as an integer.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    artifact: str = Field(min_length=1)
    positives_thresh: int = Field(default=1, ge=0)
    msg: str | None = None


class SearchRequest(BaseModel):
    """Body of /v1/search/name (SPEC §8), in strict JSON types as ScoreRequest (D14).

    The double-quote ban on `name` is a content rule (INVALID_ARTIFACT), not a
    shape rule, so it lives in the service layer — not here (SPEC §9 boundary).
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1)
    days_ago: int = Field(default=30, ge=1)
    limit: int = Field(default=10, ge=1, le=40)
    msg: str | None = None


class _VTAttributes(BaseModel):
    """The minimal attribute contract we rely on (SPEC §9, NOTES §2)."""

    model_config = ConfigDict(extra="allow")

    last_analysis_stats: dict[str, int]

    @field_validator("last_analysis_stats")
    @classmethod
    def _must_carry_malicious(cls, stats: dict[str, int]) -> dict[str, int]:
        if "malicious" not in stats:
            raise ValueError("last_analysis_stats lacks the 'malicious' bucket")
        return stats


class VTObject(BaseModel):
    """Minimal shape of a VT v3 `data` object; everything else stays opaque."""

    model_config = ConfigDict(extra="allow")

    id: str
    type: str
    attributes: _VTAttributes


def validate_vt_object(data: Any) -> None:
    """Raises pydantic.ValidationError if `data` breaks the minimal contract."""
    VTObject.model_validate(data)
