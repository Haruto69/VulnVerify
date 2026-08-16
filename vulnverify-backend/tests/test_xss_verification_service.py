from datetime import datetime, timezone

from backend.models.normalized_finding import (
    FindingSource,
    HttpRequest,
    NormalizedConfidence,
    NormalizedFinding,
    NormalizedSeverity,
    OriginalTest,
    ParameterLocation,
    TargetInfo,
    VulnerabilityCategory,
    VulnerabilityInfo,
)
from backend.models.replay_result import (
    ReplayExecution,
    ReplayRequest,
    ReplayResponse,
    ReplayResult,
)
from backend.models.verified_finding import VerificationStatus
from backend.services.xss_verification_service import (
    finalize_xss_verification,
)
from backend.verification.xss_context import (
    XssBlockingReason,
    XssSubtype,
)
from backend.verification.xss_observations import (
    XssReplayAttemptObservation,
)


def make_finding() -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-xss-001",
        finding_id="xss-001",
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40012",
            original_name="Cross Site Scripting (Reflected)",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.XSS,
            subtype="REFLECTED",
            raw_severity="High",
            normalized_severity=NormalizedSeverity.HIGH,
            raw_confidence="High",
            normalized_confidence=NormalizedConfidence.HIGH,
            cwe="CWE-79",
        ),
        target=TargetInfo(
            url="http://example.test/search?q=test",
            normalized_url="http://example.test/search?q=test",
            host="example.test",
            path="/search",
            parameter="q",
            parameter_location=ParameterLocation.QUERY,
        ),
        original_test=OriginalTest(
            payload="scanner-payload",
            evidence="scanner-evidence",
        ),
        request=HttpRequest(
            method="GET",
            url="http://example.test/search?q=test",
            path="/search",
        ),
    )


def make_replay(
    status: int = 200,
) -> ReplayResult:
    return ReplayResult(
        finding_id="xss-001",
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url="http://example.test/search?q=test",
                headers={},
                body=None,
            ),
            response=ReplayResponse(
                status=status,
                headers={},
                body="<html></html>",
            ),
        ),
        observations=[],
        errors=[],
    )


def test_service_returns_true_positive_for_marker_execution():
    result = finalize_xss_verification(
        finding=make_finding(),
        subtype=XssSubtype.REFLECTED,
        attempts=[
            XssReplayAttemptObservation(
                payload_variant_id="variant-1",
                replay=make_replay(),
                browser_completed_successfully=True,
                marker_fired=True,
                marker_fired_in_correct_context=True,
            ),
        ],
        verification_confidence=0.95,
    )

    assert (
        result.classification.status
        == VerificationStatus.TRUE_POSITIVE
    )


def test_service_returns_false_positive_for_two_encoded_variants():
    result = finalize_xss_verification(
        finding=make_finding(),
        subtype=XssSubtype.REFLECTED,
        attempts=[
            XssReplayAttemptObservation(
                payload_variant_id="variant-1",
                replay=make_replay(),
                browser_completed_successfully=True,
                payload_encoded_or_sanitized=True,
            ),
            XssReplayAttemptObservation(
                payload_variant_id="variant-2",
                replay=make_replay(),
                browser_completed_successfully=True,
                payload_encoded_or_sanitized=True,
            ),
        ],
        verification_confidence=0.90,
    )

    assert (
        result.classification.status
        == VerificationStatus.FALSE_POSITIVE
    )


def test_service_returns_inconclusive_for_missing_render_page():
    result = finalize_xss_verification(
        finding=make_finding(),
        subtype=XssSubtype.STORED,
        attempts=[
            XssReplayAttemptObservation(
                payload_variant_id="variant-1",
                replay=make_replay(),
                browser_completed_successfully=True,
            ),
        ],
        stored_injection_completed=True,
        stored_render_page_reached=False,
        blocking_reason=(
            XssBlockingReason.RENDER_PAGE_NOT_FOUND
        ),
        verification_confidence=0.20,
    )

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )


def test_service_keeps_same_variant_twice_inconclusive():
    result = finalize_xss_verification(
        finding=make_finding(),
        subtype=XssSubtype.REFLECTED,
        attempts=[
            XssReplayAttemptObservation(
                payload_variant_id="same-variant",
                replay=make_replay(),
                browser_completed_successfully=True,
                payload_encoded_or_sanitized=True,
            ),
            XssReplayAttemptObservation(
                payload_variant_id="same-variant",
                replay=make_replay(),
                browser_completed_successfully=True,
                payload_encoded_or_sanitized=True,
            ),
        ],
        verification_confidence=0.40,
    )

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )