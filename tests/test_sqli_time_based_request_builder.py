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
from backend.replay.sqli_time_based import (
    build_time_based_replay_requests,
)


def make_finding(
    *,
    parameter_location: ParameterLocation = ParameterLocation.QUERY,
    url: str = (
        "http://test.local/item?"
        "id=1%27+AND+SLEEP%285%29--+&Submit=Submit"
    ),
    category: VulnerabilityCategory = VulnerabilityCategory.SQLI,
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="SCAN-SQLI-REQUEST",
        finding_id="F-SQLI-REQUEST",
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
            url=url,
            normalized_url="http://test.local/item",
            host="test.local",
            path="/item",
            parameter="id",
            parameter_location=parameter_location,
        ),
        original_test=OriginalTest(
            payload="scanner-supplied-payload",
            evidence="scanner-evidence",
        ),
        request=HttpRequest(
            method="GET",
            url=url,
            path="/item",
            headers={
                "cookie": "session=abc123",
                "user-agent": "scanner-agent",
            },
            body=None,
        ),
    )


def test_baseline_replaces_only_tested_parameter():
    finding = make_finding()

    baseline, verification = (
        build_time_based_replay_requests(
            finding=finding,
            baseline_parameter_value="1",
        )
    )

    assert (
        baseline.url
        == "http://test.local/item?id=1&Submit=Submit"
    )

    assert verification.url == finding.request.url


def test_verification_request_remains_scanner_request():
    finding = make_finding()

    baseline, verification = (
        build_time_based_replay_requests(
            finding=finding,
            baseline_parameter_value="1",
        )
    )

    assert verification.method == finding.request.method
    assert verification.url == finding.request.url
    assert verification.headers == finding.request.headers
    assert verification.body == finding.request.body

    assert baseline.method == finding.request.method
    assert baseline.headers == finding.request.headers
    assert baseline.body == finding.request.body


def test_blank_baseline_value_is_supported():
    finding = make_finding()

    baseline, _ = build_time_based_replay_requests(
        finding=finding,
        baseline_parameter_value="",
    )

    assert (
        baseline.url
        == "http://test.local/item?id=&Submit=Submit"
    )


def test_missing_tested_parameter_is_rejected():
    finding = make_finding(
        url="http://test.local/item?other=1"
    )

    with pytest.raises(
        ValueError,
        match="was not found",
    ):
        build_time_based_replay_requests(
            finding=finding,
            baseline_parameter_value="1",
        )


def test_duplicate_tested_parameter_is_rejected():
    finding = make_finding(
        url="http://test.local/item?id=attack&id=second"
    )

    with pytest.raises(
        ValueError,
        match="multiple times",
    ):
        build_time_based_replay_requests(
            finding=finding,
            baseline_parameter_value="1",
        )


def test_non_query_location_is_not_guessed():
    finding = make_finding(
        parameter_location=ParameterLocation.FORM,
    )

    with pytest.raises(
        ValueError,
        match="QUERY parameters only",
    ):
        build_time_based_replay_requests(
            finding=finding,
            baseline_parameter_value="1",
        )


def test_non_sqli_finding_is_rejected():
    finding = make_finding(
        category=VulnerabilityCategory.XSS,
    )

    with pytest.raises(
        ValueError,
        match="non-SQLI",
    ):
        build_time_based_replay_requests(
            finding=finding,
            baseline_parameter_value="1",
        )