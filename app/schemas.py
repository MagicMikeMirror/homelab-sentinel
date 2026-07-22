from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EventIn(BaseModel):
    source: str = Field(min_length=1, max_length=120)
    event_type: str = Field(min_length=1, max_length=120)
    severity: str = Field(default="medium", pattern="^(info|low|medium|high|critical)$")
    title: str = Field(min_length=1, max_length=255)
    source_ip: str | None = None
    country: str | None = None
    scenario: str | None = None
    message: str | None = None
    seen_at: datetime | None = None
    raw_data: dict[str, Any] | None = None


class CrowdSecWebhook(BaseModel):
    source: str = Field(min_length=1, max_length=120)
    payload: Any
