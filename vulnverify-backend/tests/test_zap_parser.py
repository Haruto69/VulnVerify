import json

import pytest

from backend.parsers.zap import ZapParser


GENERIC_ZAP_REPORT = (
    "tests/fixtures/zap/zap_report.json"
)

SQLI_ZAP_REPORT = (
    "tests/fixtures/zap/zap_sqli_positive.json"
)


def read_fixture(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


def test_valid_zap_report():
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(GENERIC_ZAP_REPORT),
        scan_id="scan-test-zap",
    )

    assert findings == []


def test_invalid_json():
    parser = ZapParser()

    with pytest.raises(
        ValueError,
        match="Invalid ZAP JSON report",
    ):
        parser.parse(
            content=b"this is not json",
            scan_id="scan-test-zap",
        )


def test_non_zap_json():
    parser = ZapParser()

    content = (
        b'{"@programName": "NOT_ZAP", "site": []}'
    )

    with pytest.raises(
        ValueError,
        match="not an OWASP ZAP report",
    ):
        parser.parse(
            content=content,
            scan_id="scan-test-zap",
        )


def test_extracts_zap_alert_instances():
    parser = ZapParser()

    content = read_fixture(
        GENERIC_ZAP_REPORT
    )

    report = json.loads(
        content.decode("utf-8")
    )

    alert_instances = (
        parser._extract_alert_instances(report)
    )

    assert len(alert_instances) > 0

    alert, instance = alert_instances[0]

    assert "alert" in alert
    assert "pluginid" in alert

    assert "uri" in instance
    assert "method" in instance
    assert "request-header" in instance
    assert "response-header" in instance


def test_normalizes_real_zap_sqli_finding():
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(SQLI_ZAP_REPORT),
        scan_id="scan-sqli-001",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.scan_id == "scan-sqli-001"

    assert finding.source.scanner == "ZAP"
    assert finding.source.scanner_finding_id == "40018"

    assert (
        finding.source.original_name
        == "SQL Injection - MySQL"
    )

    assert finding.vulnerability.category == "SQLI"
    assert finding.vulnerability.subtype is None

    assert (
        finding.vulnerability.normalized_severity
        == "HIGH"
    )

    assert finding.vulnerability.raw_confidence == "2"

    assert (
        finding.vulnerability.normalized_confidence
        == "UNKNOWN"
    )

    assert finding.vulnerability.cwe == "CWE-89"

    assert finding.target.host == "127.0.0.1"

    assert (
        finding.target.path
        == "/DVWA/vulnerabilities/sqli/"
    )

    assert finding.target.parameter == "id"

    assert (
        finding.target.parameter_location
        == "QUERY"
    )

    assert finding.original_test.payload == "'"

    assert (
        finding.original_test.evidence
        == "You have an error in your SQL syntax"
    )

    assert finding.request.method == "GET"

    assert (
        finding.request.query_parameters["id"]
        == ["'"]
    )

    assert (
        finding.request.cookies["security"]
        == "low"
    )

    assert "PHPSESSID" in finding.request.cookies

    assert finding.response is not None
    assert finding.response.status_code == 200

    assert (
        "You have an error in your SQL syntax"
        in finding.response.body
    )

    assert finding.metadata["scan_timestamp"] is not None


def test_generic_report_does_not_create_false_sqli_findings():
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(GENERIC_ZAP_REPORT),
        scan_id="scan-generic-001",
    )

    assert findings == []