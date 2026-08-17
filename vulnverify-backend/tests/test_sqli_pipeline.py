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
from backend.services.pipeline_service import (
    verify_time_based_sqli_finding,
)
from backend.services.scan_service import (
    get_verified_finding,
)
from backend.verification.sqli_timing import TimingSample


def make_finding() -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="SCAN-SQLI-PIPELINE",
        finding_id="F-SQLI-PIPELINE",
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


def sample(
    number: int,
    response_time_ms: float,
) -> TimingSample:
    return TimingSample(
        request_number=number,
        timestamp=datetime.now(timezone.utc),
        status=200,
        response_time_ms=response_time_ms,
        response_length=2,
        body_fingerprint="test",
        headers={},
        errors=(),
    )


def make_replay_result(finding_id: str) -> ReplayResult:
    return ReplayResult(
        finding_id=finding_id,
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url="http://test.local/item?id=1",
                headers={},
                body=None,
            ),
            response=ReplayResponse(
                status=200,
                headers={},
                body="<html></html>",
            ),
        ),
        observations=[],
        errors=[],
    )


def test_time_based_pipeline_verifies_and_persists_result():
    finding = make_finding()

    result = verify_time_based_sqli_finding(
        finding=finding,
        replay_result=make_replay_result(finding.finding_id),
        baseline_samples=[
            sample(1, 100.0),
            sample(2, 105.0),
            sample(3, 95.0),
            sample(4, 100.0),
            sample(5, 100.0),
        ],
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

    stored = get_verified_finding(
        scan_id=finding.scan_id,
        finding_id=finding.finding_id,
    )

    assert stored is not None
    assert stored.finding_id == finding.finding_id

    assert (
        stored.classification.status
        == VerificationStatus.TRUE_POSITIVE
    )


def test_time_based_reverification_replaces_previous_result():
    finding = make_finding()

    verify_time_based_sqli_finding(
        finding=finding,
        replay_result=make_replay_result(finding.finding_id),
        baseline_samples=[
            sample(1, 100.0),
            sample(2, 105.0),
            sample(3, 95.0),
            sample(4, 100.0),
            sample(5, 100.0),
        ],
        verification_samples=[
            sample(1, 2500.0),
            sample(2, 2600.0),
            sample(3, 2700.0),
        ],
        verification_confidence=0.95,
    )

    second = verify_time_based_sqli_finding(
        finding=finding,
        replay_result=make_replay_result(finding.finding_id),
        baseline_samples=[
            sample(1, 100.0),
            sample(2, 105.0),
            sample(3, 95.0),
            sample(4, 100.0),
            sample(5, 100.0),
        ],
        verification_samples=[
            sample(1, 110.0),
            sample(2, 105.0),
            sample(3, 115.0),
        ],
        verification_confidence=0.90,
    )

    stored = get_verified_finding(
        scan_id=finding.scan_id,
        finding_id=finding.finding_id,
    )

    assert (
        second.classification.status
        == VerificationStatus.FALSE_POSITIVE
    )

    assert (
        stored.classification.status
        == VerificationStatus.FALSE_POSITIVE
    )