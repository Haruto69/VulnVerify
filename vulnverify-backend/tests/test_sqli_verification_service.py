from datetime import datetime, timezone

import pytest

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
from backend.services.sqli_verification_service import (
    finalize_time_based_sqli_verification,
)
from backend.verification.sqli_timing import TimingSample


def make_finding(
    category: VulnerabilityCategory = VulnerabilityCategory.SQLI,
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="SCAN-SQLI-SERVICE",
        finding_id="F-SQLI-SERVICE",
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40018",
            original_name="SQL Injection",
        ),
        vulnerability=VulnerabilityInfo(
            category=category,
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


def stable_baseline() -> list[TimingSample]:
    return [
        sample(1, 100.0),
        sample(2, 105.0),
        sample(3, 95.0),
        sample(4, 100.0),
        sample(5, 100.0),
    ]


def test_service_returns_true_positive():
    result = finalize_time_based_sqli_verification(
        finding=make_finding(),
        baseline_samples=stable_baseline(),
        verification_samples=[
            sample(1, 2500.0),
            sample(2, 2600.0),
            sample(3, 2700.0),
        ],
        verification_confidence=0.95,
    )

    assert (
        result.classification.status
        == VerificationStatus.TRUE_POSITIVE
    )

    assert (
        result.verification_method
        == "sqli_time_based_rule_v1"
    )


def test_service_returns_false_positive_when_delay_absent():
    result = finalize_time_based_sqli_verification(
        finding=make_finding(),
        baseline_samples=stable_baseline(),
        verification_samples=[
            sample(1, 110.0),
            sample(2, 105.0),
            sample(3, 115.0),
        ],
        verification_confidence=0.90,
    )

    assert (
        result.classification.status
        == VerificationStatus.FALSE_POSITIVE
    )


def test_service_returns_inconclusive_when_network_explanation_exists():
    result = finalize_time_based_sqli_verification(
        finding=make_finding(),
        baseline_samples=stable_baseline(),
        verification_samples=[
            sample(1, 2500.0),
            sample(2, 2600.0),
            sample(3, 2700.0),
        ],
        credible_network_or_server_explanation=True,
        verification_confidence=0.40,
    )

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )


def test_service_rejects_non_sqli_finding():
    with pytest.raises(
        ValueError,
        match="non-SQLI",
    ):
        finalize_time_based_sqli_verification(
            finding=make_finding(
                category=VulnerabilityCategory.XSS
            ),
            baseline_samples=stable_baseline(),
            verification_samples=[
                sample(1, 2500.0),
                sample(2, 2600.0),
                sample(3, 2700.0),
            ],
            verification_confidence=0.95,
        )