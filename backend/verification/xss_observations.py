from pydantic import BaseModel

from backend.models.replay_result import ReplayResult


class XssReplayAttemptObservation(BaseModel):
    payload_variant_id: str

    replay: ReplayResult | None = None

    browser_completed_successfully: bool = False
    browser_error: str | None = None

    marker_fired: bool = False
    marker_fired_in_correct_context: bool = False

    payload_reflected_or_rendered: bool = False
    payload_unescaped_in_executable_context: bool = False
    no_interfering_csp_encoding_or_sanitization: bool = False

    payload_absent: bool = False
    payload_encoded_or_sanitized: bool = False
    payload_only_in_non_executable_context: bool = False
    payload_execution_vector_blocked_by_verified_policy: bool = False

    dom_attacker_controlled_data_reached_sink: bool | None = None