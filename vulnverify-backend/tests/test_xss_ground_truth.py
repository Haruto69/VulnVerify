from backend.models.verified_finding import VerificationStatus
from backend.verification.xss import classify_xss
from backend.verification.xss_context import (
    XssBlockingReason,
    XssSubtype,
    XssVerificationContext,
)


def classify(context: XssVerificationContext):
    status, _ = classify_xss(context)
    return status


def test_xss_001_reflected_true_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        replay_completed_successfully=True,
        independent_replay_attempts=1,
        marker_fired=True,
        marker_fired_in_correct_context=True,
        verification_confidence=0.95,
    )

    assert classify(context) == VerificationStatus.TRUE_POSITIVE


def test_xss_002_reflected_encoded_false_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        replay_completed_successfully=True,
        independent_replay_attempts=2,
        payload_encoded_or_sanitized=True,
        marker_never_fired_across_independent_attempts=True,
        verification_confidence=0.90,
    )

    assert classify(context) == VerificationStatus.FALSE_POSITIVE


def test_xss_003_server_error_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        blocking_reason=XssBlockingReason.TARGET_SERVER_ERROR,
        verification_confidence=0.30,
    )

    assert classify(context) == VerificationStatus.INCONCLUSIVE


def test_xss_004_stored_true_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.STORED,
        replay_completed_successfully=True,
        stored_injection_completed=True,
        stored_render_page_reached=True,
        marker_fired=True,
        marker_fired_in_correct_context=True,
        verification_confidence=0.95,
    )

    assert classify(context) == VerificationStatus.TRUE_POSITIVE


def test_xss_005_stored_sanitized_false_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.STORED,
        replay_completed_successfully=True,
        independent_replay_attempts=2,
        stored_injection_completed=True,
        stored_render_page_reached=True,
        payload_encoded_or_sanitized=True,
        marker_never_fired_across_independent_attempts=True,
        verification_confidence=0.90,
    )

    assert classify(context) == VerificationStatus.FALSE_POSITIVE


def test_xss_006_missing_render_page_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.STORED,
        stored_injection_completed=True,
        stored_render_page_reached=False,
        blocking_reason=XssBlockingReason.RENDER_PAGE_NOT_FOUND,
        verification_confidence=0.20,
    )

    assert classify(context) == VerificationStatus.INCONCLUSIVE


def test_xss_007_dom_true_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.DOM_BASED,
        replay_completed_successfully=True,
        dom_attacker_controlled_data_reached_sink=True,
        marker_fired=True,
        marker_fired_in_correct_context=True,
        verification_confidence=0.95,
    )

    assert classify(context) == VerificationStatus.TRUE_POSITIVE


def test_xss_008_dom_sanitized_false_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.DOM_BASED,
        replay_completed_successfully=True,
        independent_replay_attempts=2,
        dom_attacker_controlled_data_reached_sink=True,
        payload_encoded_or_sanitized=True,
        marker_never_fired_across_independent_attempts=True,
        verification_confidence=0.90,
    )

    assert classify(context) == VerificationStatus.FALSE_POSITIVE


def test_xss_009_browser_failure_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.DOM_BASED,
        blocking_reason=XssBlockingReason.BROWSER_RENDER_FAILURE,
        verification_confidence=0.20,
    )

    assert classify(context) == VerificationStatus.INCONCLUSIVE


def test_xss_010_session_failure_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        blocking_reason=XssBlockingReason.AUTH_SESSION_FAILURE,
        verification_confidence=0.20,
    )

    assert classify(context) == VerificationStatus.INCONCLUSIVE


def test_xss_011_csrf_failure_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.STORED,
        blocking_reason=XssBlockingReason.CSRF_TOKEN_FAILURE,
        verification_confidence=0.20,
    )

    assert classify(context) == VerificationStatus.INCONCLUSIVE


def test_xss_012_waf_request_block_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        blocking_reason=XssBlockingReason.WAF_REQUEST_BLOCK,
        verification_confidence=0.20,
    )

    assert classify(context) == VerificationStatus.INCONCLUSIVE


def test_xss_013_timeout_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        blocking_reason=XssBlockingReason.TARGET_TIMEOUT,
        verification_confidence=0.20,
    )

    assert classify(context) == VerificationStatus.INCONCLUSIVE


def test_xss_014_render_page_unreachable_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.STORED,
        stored_injection_completed=True,
        stored_render_page_reached=False,
        blocking_reason=XssBlockingReason.RENDER_PAGE_UNREACHABLE,
        verification_confidence=0.20,
    )

    assert classify(context) == VerificationStatus.INCONCLUSIVE


def test_xss_015_insufficient_evidence_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        blocking_reason=XssBlockingReason.INSUFFICIENT_EVIDENCE,
        verification_confidence=0.20,
    )

    assert classify(context) == VerificationStatus.INCONCLUSIVE


def test_xss_016_invalid_replay_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        blocking_reason=XssBlockingReason.REPLAY_REQUEST_INVALID,
        verification_confidence=0.20,
    )

    assert classify(context) == VerificationStatus.INCONCLUSIVE


def test_xss_017_environment_drift_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.STORED,
        blocking_reason=XssBlockingReason.ENVIRONMENT_DRIFT,
        verification_confidence=0.20,
    )

    assert classify(context) == VerificationStatus.INCONCLUSIVE


def test_xss_018_csp_blocked_false_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        replay_completed_successfully=True,
        independent_replay_attempts=2,
        payload_reflected_or_rendered=True,
        payload_execution_vector_blocked_by_verified_policy=True,
        marker_never_fired_across_independent_attempts=True,
        verification_confidence=0.90,
    )

    assert classify(context) == VerificationStatus.FALSE_POSITIVE