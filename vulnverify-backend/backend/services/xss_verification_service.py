from backend.models.normalized_finding import NormalizedFinding
from backend.models.verified_finding import VerifiedFinding
from backend.verification.xss import verify_xss
from backend.verification.xss_context import (
    XssBlockingReason,
    XssSubtype,
)
from backend.verification.xss_context_builder import (
    build_xss_verification_context,
)
from backend.verification.xss_observations import (
    XssReplayAttemptObservation,
)


def finalize_xss_verification(
    *,
    finding: NormalizedFinding,
    subtype: XssSubtype,
    attempts: list[XssReplayAttemptObservation],
    verification_confidence: float,
    blocking_reason: XssBlockingReason | None = None,
    stored_injection_completed: bool | None = None,
    stored_render_page_reached: bool | None = None,
    request_reference: str | None = None,
    response_reference: str | None = None,
) -> VerifiedFinding:
    context = build_xss_verification_context(
        subtype=subtype,
        attempts=attempts,
        verification_confidence=verification_confidence,
        blocking_reason=blocking_reason,
        stored_injection_completed=stored_injection_completed,
        stored_render_page_reached=stored_render_page_reached,
        request_reference=request_reference,
        response_reference=response_reference,
    )

    return verify_xss(
        finding=finding,
        context=context,
    )