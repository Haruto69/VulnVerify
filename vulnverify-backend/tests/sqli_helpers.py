"""
Shared deterministic builders for the SQLi verification test batch.

Nothing here performs network access or real timing. Every helper
returns a fully constructed in-memory object so the SQLi verification
rules can be exercised as pure functions.
"""

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
from backend.verification.sqli_response import ResponseObservation
from backend.verification.sqli_timing import TimingSample


# A body long enough that a single token change stays well above the
# 0.98 baseline similarity floor, which is what the non-time baseline
# rule actually measures.
STABLE_BODY = (
    "<html><body><h1>Catalog</h1>"
    + "Product listing row. " * 20
    + "</body></html>"
)

DIFFERENT_BODY = (
    "<html><body><h1>Error</h1>"
    "Something else entirely different is rendered here."
    "</body></html>"
)

GENERIC_APPLICATION_ERROR_BODY = (
    "<html><body><h1>Oops</h1>"
    "An unexpected application error occurred. Please try again later."
    "</body></html>"
)

MYSQL_ERROR_BODY = (
    "<html><body>"
    "You have an error in your SQL syntax near '1'"
    "</body></html>"
)

MYSQL_COLUMN_COUNT_BODY = (
    "<html><body>"
    "The used SELECT statements have a different number of columns"
    "</body></html>"
)


def make_sqli_finding(
    *,
    scan_id: str = "SCAN-SQLI-TEST",
    finding_id: str = "F-SQLI-TEST",
    subtype: str = "ERROR_BASED",
    category: VulnerabilityCategory = VulnerabilityCategory.SQLI,
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id=scan_id,
        finding_id=finding_id,
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40018",
            original_name="SQL Injection",
        ),
        vulnerability=VulnerabilityInfo(
            category=category,
            subtype=subtype,
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


def make_replay_result(
    *,
    finding_id: str = "F-SQLI-TEST",
    status: int | None = 200,
    body: str | None = STABLE_BODY,
    executed: bool = True,
    errors: list[str] | None = None,
) -> ReplayResult:
    return ReplayResult(
        finding_id=finding_id,
        replay=ReplayExecution(
            executed=executed,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url="http://test.local/item?id=1",
                headers={},
                body=None,
            ),
            response=ReplayResponse(
                status=status,
                headers={},
                body=body,
            ),
        ),
        observations=[],
        errors=errors or [],
    )


def observation(
    body: str = STABLE_BODY,
    *,
    status: int | None = 200,
    valid: bool = True,
    failure_reasons: tuple[str, ...] = (),
) -> ResponseObservation:
    return ResponseObservation(
        status_code=status,
        body=body,
        valid=valid,
        failure_reasons=failure_reasons,
    )


def stable_baseline(
    count: int = 3,
    body: str = STABLE_BODY,
    *,
    status: int = 200,
) -> list[ResponseObservation]:
    return [
        observation(body, status=status)
        for _ in range(count)
    ]


def invalid_baseline(
    reason: str,
    count: int = 3,
    *,
    status: int | None = 401,
) -> list[ResponseObservation]:
    return [
        observation(
            "",
            status=status,
            valid=False,
            failure_reasons=(reason,),
        )
        for _ in range(count)
    ]


def timing_sample(
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


def stable_timing_baseline() -> list[TimingSample]:
    """Five valid samples, MAD/median well under 0.20."""

    return [
        timing_sample(1, 100.0),
        timing_sample(2, 105.0),
        timing_sample(3, 95.0),
        timing_sample(4, 100.0),
        timing_sample(5, 100.0),
    ]


def unstable_timing_baseline() -> list[TimingSample]:
    """Five valid samples with MAD/median above 0.20."""

    return [
        timing_sample(1, 60.0),
        timing_sample(2, 100.0),
        timing_sample(3, 140.0),
        timing_sample(4, 100.0),
        timing_sample(5, 160.0),
    ]


def delayed_verification_trials() -> list[TimingSample]:
    return [
        timing_sample(1, 2500.0),
        timing_sample(2, 2600.0),
        timing_sample(3, 2700.0),
    ]


def undelayed_verification_trials() -> list[TimingSample]:
    return [
        timing_sample(1, 110.0),
        timing_sample(2, 105.0),
        timing_sample(3, 115.0),
    ]
