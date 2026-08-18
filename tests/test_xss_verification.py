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
from backend.models.verified_finding import VerificationStatus
from backend.verification.xss import (
    classify_xss,
    verify_xss,
)
from backend.verification.xss_context import (
    XssBlockingReason,
    XssSubtype,
    XssVerificationContext,
)


def make_xss_finding(
    *,
    subtype: str = "REFLECTED",
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="SCAN-XSS-001",
        finding_id="F-XSS-001",
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40012",
            original_name="Cross Site Scripting (Reflected)",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.XSS,
            subtype=subtype,
            raw_severity="High",
            normalized_severity=NormalizedSeverity.HIGH,
            raw_confidence="High",
            normalized_confidence=NormalizedConfidence.HIGH,
            cwe="CWE-79",
        ),
        target=TargetInfo(
            url="http://test.local/search?q=test",
            normalized_url="http://test.local/search?q=test",
            host="test.local",
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
            url="http://test.local/search?q=test",
            path="/search",
        ),
    )


def test_reflected_marker_execution_is_true_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        replay_completed_successfully=True,
        independent_replay_attempts=1,
        marker_fired=True,
        marker_fired_in_correct_context=True,
        verification_confidence=0.95,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.TRUE_POSITIVE


def test_reflection_alone_is_not_true_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        replay_completed_successfully=True,
        independent_replay_attempts=1,
        payload_reflected_or_rendered=True,
        verification_confidence=0.40,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_static_context_requires_second_confirmation():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        replay_completed_successfully=True,
        independent_replay_attempts=1,
        payload_reflected_or_rendered=True,
        payload_unescaped_in_executable_context=True,
        no_interfering_csp_encoding_or_sanitization=True,
        second_confirmation_unescaped_in_executable_context=False,
        verification_confidence=0.70,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_static_context_with_second_confirmation_is_true_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        replay_completed_successfully=True,
        independent_replay_attempts=2,
        payload_reflected_or_rendered=True,
        payload_unescaped_in_executable_context=True,
        no_interfering_csp_encoding_or_sanitization=True,
        second_confirmation_unescaped_in_executable_context=True,
        verification_confidence=0.90,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.TRUE_POSITIVE


def test_encoded_payload_is_false_positive_after_two_attempts():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        replay_completed_successfully=True,
        independent_replay_attempts=2,
        payload_encoded_or_sanitized=True,
        marker_never_fired_across_independent_attempts=True,
        verification_confidence=0.90,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.FALSE_POSITIVE


def test_payload_absent_is_false_positive_after_two_attempts():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        replay_completed_successfully=True,
        independent_replay_attempts=2,
        payload_absent=True,
        marker_never_fired_across_independent_attempts=True,
        verification_confidence=0.90,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.FALSE_POSITIVE


def test_verified_csp_or_waf_payload_block_is_false_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        replay_completed_successfully=True,
        independent_replay_attempts=2,
        payload_execution_vector_blocked_by_verified_policy=True,
        marker_never_fired_across_independent_attempts=True,
        verification_confidence=0.90,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.FALSE_POSITIVE


def test_single_failed_execution_attempt_is_not_false_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        replay_completed_successfully=True,
        independent_replay_attempts=1,
        payload_encoded_or_sanitized=True,
        marker_never_fired_across_independent_attempts=True,
        verification_confidence=0.40,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_stored_marker_execution_is_true_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.STORED,
        replay_completed_successfully=True,
        independent_replay_attempts=1,
        stored_injection_completed=True,
        stored_render_page_reached=True,
        marker_fired=True,
        marker_fired_in_correct_context=True,
        verification_confidence=0.95,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.TRUE_POSITIVE


def test_stored_missing_render_page_is_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.STORED,
        replay_completed_successfully=True,
        stored_injection_completed=True,
        stored_render_page_reached=False,
        blocking_reason=XssBlockingReason.RENDER_PAGE_NOT_FOUND,
        verification_confidence=0.20,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_stored_missing_render_page_never_becomes_false_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.STORED,
        replay_completed_successfully=True,
        independent_replay_attempts=2,
        stored_injection_completed=True,
        stored_render_page_reached=False,
        payload_absent=True,
        marker_never_fired_across_independent_attempts=True,
        verification_confidence=0.20,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_dom_requires_sink_reach_for_true_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.DOM_BASED,
        replay_completed_successfully=True,
        marker_fired=True,
        marker_fired_in_correct_context=True,
        dom_attacker_controlled_data_reached_sink=False,
        verification_confidence=0.40,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_dom_sink_and_marker_execution_is_true_positive():
    context = XssVerificationContext(
        subtype=XssSubtype.DOM_BASED,
        replay_completed_successfully=True,
        marker_fired=True,
        marker_fired_in_correct_context=True,
        dom_attacker_controlled_data_reached_sink=True,
        verification_confidence=0.95,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.TRUE_POSITIVE


def test_dom_sink_not_reached_is_false_positive_after_two_attempts():
    context = XssVerificationContext(
        subtype=XssSubtype.DOM_BASED,
        replay_completed_successfully=True,
        independent_replay_attempts=2,
        dom_attacker_controlled_data_reached_sink=False,
        marker_never_fired_across_independent_attempts=True,
        verification_confidence=0.90,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.FALSE_POSITIVE


def test_auth_failure_is_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        blocking_reason=XssBlockingReason.AUTH_SESSION_FAILURE,
        verification_confidence=0.20,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_csrf_refresh_failure_is_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        blocking_reason=XssBlockingReason.CSRF_TOKEN_FAILURE,
        verification_confidence=0.20,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_server_error_is_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        blocking_reason=XssBlockingReason.TARGET_SERVER_ERROR,
        verification_confidence=0.20,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_waf_blocking_replay_request_is_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        blocking_reason=XssBlockingReason.WAF_REQUEST_BLOCK,
        verification_confidence=0.20,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_unknown_subtype_is_inconclusive():
    context = XssVerificationContext(
        subtype=XssSubtype.UNKNOWN,
        verification_confidence=0.20,
    )

    status, _ = classify_xss(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_verify_xss_builds_verified_finding():
    finding = make_xss_finding()

    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        replay_completed_successfully=True,
        marker_fired=True,
        marker_fired_in_correct_context=True,
        verification_confidence=0.95,
        request_reference="REQ-XSS-001",
        response_reference="RES-XSS-001",
    )

    result = verify_xss(
        finding=finding,
        context=context,
    )

    assert (
        result.classification.status
        == VerificationStatus.TRUE_POSITIVE
    )
    assert result.classification.confidence == 0.95
    assert result.verification_method == "xss_reflected_rule_v1"
    assert "execution_marker_fired" in result.evidence.indicators
    assert result.evidence.request_reference == "REQ-XSS-001"
    assert result.evidence.response_reference == "RES-XSS-001"