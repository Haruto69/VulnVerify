import pytest

from backend.models.normalized_finding import (
    FindingContext,
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
from backend.replay.xss_query_mutation import (
    build_reflected_xss_variant_request,
)


def make_finding(
    url: str = "http://example.test/search?q=original",
    parameter: str | None = "q",
    parameter_location: ParameterLocation = ParameterLocation.QUERY,
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-xss-001",
        finding_id="xss-001",
        source=FindingSource(
            scanner="Burp",
            scanner_finding_id="1",
            original_name="Cross-site Scripting (reflected)",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.XSS,
            subtype="Cross-site Scripting (reflected)",
            raw_severity="High",
            normalized_severity=NormalizedSeverity.HIGH,
            raw_confidence="Firm",
            normalized_confidence=NormalizedConfidence.MEDIUM,
            cwe="CWE-79",
        ),
        target=TargetInfo(
            url=url,
            normalized_url=url,
            host="example.test",
            path="/search",
            parameter=parameter,
            parameter_location=parameter_location,
        ),
        original_test=OriginalTest(payload=None, evidence=None),
        request=HttpRequest(
            method="GET",
            url=url,
            path="/search",
        ),
        context=FindingContext(),
    )


def test_query_parameter_is_replaced():
    finding = make_finding()

    request = build_reflected_xss_variant_request(
        finding=finding,
        payload="<script>x</script>",
    )

    assert (
        request.url
        == "http://example.test/search?q=%3Cscript%3Ex%3C%2Fscript%3E"
    )
    assert request.method == "GET"


def test_missing_parameter_is_rejected():
    finding = make_finding(
        parameter=None,
        parameter_location=ParameterLocation.UNKNOWN,
    )

    with pytest.raises(ValueError):
        build_reflected_xss_variant_request(
            finding=finding,
            payload="x",
        )


def test_non_query_parameter_location_is_rejected():
    finding = make_finding(
        parameter="q",
        parameter_location=ParameterLocation.FORM,
    )

    with pytest.raises(ValueError):
        build_reflected_xss_variant_request(
            finding=finding,
            payload="x",
        )


def test_parameter_not_present_in_url_is_rejected():
    finding = make_finding(
        url="http://example.test/search?other=1",
        parameter="q",
    )

    with pytest.raises(ValueError):
        build_reflected_xss_variant_request(
            finding=finding,
            payload="x",
        )


def test_multiple_occurrences_of_parameter_are_rejected():
    finding = make_finding(
        url="http://example.test/search?q=1&q=2",
        parameter="q",
    )

    with pytest.raises(ValueError):
        build_reflected_xss_variant_request(
            finding=finding,
            payload="x",
        )


def test_other_query_parameters_are_preserved():
    finding = make_finding(
        url="http://example.test/search?a=1&q=original&b=2",
        parameter="q",
    )

    request = build_reflected_xss_variant_request(
        finding=finding,
        payload="marker",
    )

    assert "a=1" in request.url
    assert "b=2" in request.url
    assert "q=marker" in request.url
