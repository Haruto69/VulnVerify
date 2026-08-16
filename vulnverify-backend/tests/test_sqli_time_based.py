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
from backend.models.verified_finding import VerificationStatus
from backend.verification.sqli_time_based import (
    classify_time_based_sqli,
    verify_time_based_sqli,
)
from backend.verification.sqli_time_based_context import (
    build_sqli_time_based_context,
)
from backend.verification.sqli_timing import TimingSample


def sample(
    number: int,
    response_time_ms: float,
    status: int | None = 200,
) -> TimingSample:
    return TimingSample(
        request_number=number,
        timestamp=datetime.now(timezone.utc),
        status=status,
        response_time_ms=response_time_ms,
        response_length=2,
        body_fingerprint="test",
        headers={},
        errors=(),
    )


def stable_baseline():
    return [
        sample(1, 100.0),
        sample(2, 105.0),
        sample(3, 95.0),
        sample(4, 100.0),
        sample(5, 100.0),
    ]


def unstable_baseline():
    return [
        sample(1, 60.0),
        sample(2, 100.0),
        sample(3, 140.0),
        sample(4, 100.0),
        sample(5, 160.0),
    ]


def make_finding() -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="SCAN-SQLI-001",
        finding_id="F-SQLI-001",
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40018",
            original_name="SQL Injection",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.SQLI,
            subtype="TIME_BASED",
            raw_severity="High",
            normalized_severity=NormalizedSeverity.HIGH,
            raw_confidence="Medium",
            normalized_confidence=NormalizedConfidence.MEDIUM,
            cwe="CWE-89",
        ),
        target=TargetInfo(
            url="http://test.local/item?id=1",
            normalized_url="http://test.local/item?id=1",
            host="test.local",
            path="/item",
            parameter="id",
            parameter_location=ParameterLocation.QUERY,
        ),
        original_test=OriginalTest(
            payload="scanner-supplied-payload",
            evidence="scanner-evidence",
        ),
        request=HttpRequest(
            method="GET",
            url="http://test.local/item?id=1",
            path="/item",
        ),
    )


def test_time_based_true_positive():
    context = build_sqli_time_based_context(
        baseline_samples=stable_baseline(),
        verification_samples=[
            sample(1, 2500.0),
            sample(2, 2600.0),
            sample(3, 150.0),
        ],
        verification_confidence=0.95,
    )

    status, _ = classify_time_based_sqli(context)

    assert status == VerificationStatus.TRUE_POSITIVE


def test_time_based_false_positive_when_delay_absent():
    context = build_sqli_time_based_context(
        baseline_samples=stable_baseline(),
        verification_samples=[
            sample(1, 110.0),
            sample(2, 105.0),
            sample(3, 115.0),
        ],
        verification_confidence=0.90,
    )

    status, _ = classify_time_based_sqli(context)

    assert status == VerificationStatus.FALSE_POSITIVE


def test_time_based_inconclusive_for_unstable_baseline():
    context = build_sqli_time_based_context(
        baseline_samples=unstable_baseline(),
        verification_samples=[
            sample(1, 2500.0),
            sample(2, 2600.0),
            sample(3, 2700.0),
        ],
        verification_confidence=0.40,
    )

    assert context.baseline_statistics is not None
    assert context.baseline_statistics.mad_ms == 40.0
    assert context.baseline_stability.stable is False

    status, _ = classify_time_based_sqli(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_time_based_inconclusive_without_three_valid_trials():
    context = build_sqli_time_based_context(
        baseline_samples=stable_baseline(),
        verification_samples=[
            sample(1, 2500.0),
            sample(2, 2600.0),
            sample(3, 50.0, status=429),
        ],
        verification_confidence=0.40,
    )

    status, _ = classify_time_based_sqli(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_time_based_inconclusive_with_network_explanation():
    context = build_sqli_time_based_context(
        baseline_samples=stable_baseline(),
        verification_samples=[
            sample(1, 2500.0),
            sample(2, 2600.0),
            sample(3, 2700.0),
        ],
        credible_network_or_server_explanation=True,
        verification_confidence=0.40,
    )

    status, _ = classify_time_based_sqli(context)

    assert status == VerificationStatus.INCONCLUSIVE


def test_one_delayed_trial_is_false_positive():
    context = build_sqli_time_based_context(
        baseline_samples=stable_baseline(),
        verification_samples=[
            sample(1, 2500.0),
            sample(2, 110.0),
            sample(3, 120.0),
        ],
        verification_confidence=0.90,
    )

    status, _ = classify_time_based_sqli(context)

    assert status == VerificationStatus.FALSE_POSITIVE


def test_verify_time_based_builds_verified_finding():
    context = build_sqli_time_based_context(
        baseline_samples=stable_baseline(),
        verification_samples=[
            sample(1, 2500.0),
            sample(2, 2600.0),
            sample(3, 2700.0),
        ],
        verification_confidence=0.95,
    )

    result = verify_time_based_sqli(
        finding=make_finding(),
        context=context,
    )

    assert (
        result.classification.status
        == VerificationStatus.TRUE_POSITIVE
    )

    assert result.classification.confidence == 0.95

    assert (
        result.verification_method
        == "sqli_time_based_rule_v1"
    )

    assert any(
        indicator.startswith("baseline_median_ms:")
        for indicator in result.evidence.indicators
    )

    assert any(
        indicator.startswith("timing_ratio:")
        for indicator in result.evidence.indicators
    )