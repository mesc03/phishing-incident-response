from datetime import datetime
from enum import Enum

from pydantic import BaseModel, field_validator


class IOCType(str, Enum):
    ip = "ip"
    hash = "hash"
    domain = "domain"
    url = "url"


class IOCSubmitRequest(BaseModel):
    """What the client sends when submitting an IOC for lookup."""
    ioc_type: IOCType
    value: str

    @field_validator("value")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("value cannot be empty")
        return v


class EnrichmentResultResponse(BaseModel):
    """A single source's result, returned as part of the IOC response."""
    source: str
    score: float
    verdict: str  # clean, suspicious, malicious

    model_config = {"from_attributes": True}


class IOCResponse(BaseModel):
    """What the API returns after looking up an IOC."""
    id: int
    ioc_type: IOCType
    value: str
    first_seen: datetime
    last_seen: datetime
    enrichment_results: list[EnrichmentResultResponse] = []

    model_config = {"from_attributes": True}