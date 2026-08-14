from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class VulnerabilityCategory(str, Enum):
    SQLI = "SQLI"
    CSRF = "CSRF"
    XSS = "XSS"


class NormalizedSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class NormalizedConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"
    UNKNOWN = "UNKNOWN"


class ParameterLocation(str, Enum):
    QUERY = "QUERY"
    FORM = "FORM"
    JSON = "JSON"
    HEADER = "HEADER"
    COOKIE = "COOKIE"
    PATH = "PATH"
    UNKNOWN = "UNKNOWN"


class RequirementState(str, Enum):
    YES = "YES"
    NO = "NO"
    UNKNOWN = "UNKNOWN"


class FindingSource(BaseModel):
    scanner: str
    scanner_finding_id: str | None = None
    original_name: str


class VulnerabilityInfo(BaseModel):
    category: VulnerabilityCategory
    subtype: str | None = None

    raw_severity: str
    normalized_severity: NormalizedSeverity

    raw_confidence: str | None = None
    normalized_confidence: NormalizedConfidence

    cwe: str | None = None


class TargetInfo(BaseModel):
    url: str
    normalized_url: str

    host: str
    path: str

    parameter: str | None = None
    parameter_location: ParameterLocation = ParameterLocation.UNKNOWN


class OriginalTest(BaseModel):
    payload: str | None = None
    evidence: str | None = None


class HttpRequest(BaseModel):
    method: str
    url: str
    path: str

    query_parameters: dict[str, list[str]] = Field(default_factory=dict)

    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)

    body: str | None = None
    content_type: str | None = None

    raw: str | None = None


class HttpResponse(BaseModel):
    status_code: int

    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)

    body: str | None = None

    raw: str | None = None
    response_time_ms: float | None = None


class FindingContext(BaseModel):
    authentication_required: RequirementState = RequirementState.UNKNOWN
    session_required: RequirementState = RequirementState.UNKNOWN


class NormalizedFinding(BaseModel):
    schema_version: Literal["1.0"] = "1.0"

    scan_id: str
    finding_id: str

    source: FindingSource
    vulnerability: VulnerabilityInfo
    target: TargetInfo

    original_test: OriginalTest

    request: HttpRequest
    response: HttpResponse | None = None

    context: FindingContext = Field(default_factory=FindingContext)

    references: list[str] = Field(default_factory=list)

    metadata: dict[str, Any] = Field(default_factory=dict)