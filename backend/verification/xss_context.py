from enum import Enum

from pydantic import BaseModel, Field


class XssSubtype(str, Enum):
    REFLECTED = "REFLECTED"
    STORED = "STORED"
    DOM_BASED = "DOM_BASED"
    UNKNOWN = "UNKNOWN"


class XssBlockingReason(str, Enum):
    AUTH_SESSION_FAILURE = "AUTH_SESSION_FAILURE"
    CSRF_TOKEN_FAILURE = "CSRF_TOKEN_FAILURE"

    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    TARGET_TIMEOUT = "TARGET_TIMEOUT"
    TARGET_SERVER_ERROR = "TARGET_SERVER_ERROR"

    RENDER_PAGE_NOT_FOUND = "RENDER_PAGE_NOT_FOUND"
    RENDER_PAGE_UNREACHABLE = "RENDER_PAGE_UNREACHABLE"

    BROWSER_RENDER_FAILURE = "BROWSER_RENDER_FAILURE"
    ENVIRONMENT_DRIFT = "ENVIRONMENT_DRIFT"

    WAF_REQUEST_BLOCK = "WAF_REQUEST_BLOCK"

    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    REPLAY_REQUEST_INVALID = "REPLAY_REQUEST_INVALID"


class XssVerificationContext(BaseModel):
    subtype: XssSubtype

    replay_completed_successfully: bool = False
    independent_replay_attempts: int = Field(default=0, ge=0)

    marker_fired: bool = False
    marker_fired_in_correct_context: bool = False

    payload_reflected_or_rendered: bool = False
    payload_unescaped_in_executable_context: bool = False
    no_interfering_csp_encoding_or_sanitization: bool = False

    second_confirmation_unescaped_in_executable_context: bool = False

    payload_absent: bool = False
    payload_encoded_or_sanitized: bool = False
    payload_only_in_non_executable_context: bool = False
    payload_execution_vector_blocked_by_verified_policy: bool = False

    marker_never_fired_across_independent_attempts: bool = False

    stored_injection_completed: bool | None = None
    stored_render_page_reached: bool | None = None

    dom_attacker_controlled_data_reached_sink: bool | None = None

    blocking_reason: XssBlockingReason | None = None

    verification_confidence: float = Field(ge=0.0, le=1.0)

    request_reference: str | None = None
    response_reference: str | None = None