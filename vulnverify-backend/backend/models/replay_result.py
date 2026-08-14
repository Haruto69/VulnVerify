from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ReplayRequest(BaseModel):
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


class ReplayResponse(BaseModel):
    status: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


class ReplayObservation(BaseModel):
    indicator: str
    matched: bool


class ReplayExecution(BaseModel):
    executed: bool
    timestamp: datetime
    request: ReplayRequest
    response: ReplayResponse


class ReplayResult(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    finding_id: str
    replay: ReplayExecution
    observations: list[ReplayObservation] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)