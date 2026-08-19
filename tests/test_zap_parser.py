import json

import pytest

from backend.parsers.zap import ZapParser


GENERIC_ZAP_REPORT = (
    "tests/fixtures/zap/zap_report.json"
)

SQLI_ZAP_REPORT = (
    "tests/fixtures/zap/zap_sqli_positive.json"
)

XSS_ZAP_REPORT = (
    "tests/fixtures/zap/zap_xss_positive.json"
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


def make_alert(pluginid, alert_name, **overrides):
    alert = {
        "pluginid": pluginid,
        "alertRef": pluginid,
        "alert": alert_name,
        "name": alert_name,
        "riskcode": "3",
        "confidence": "2",
        "cweid": overrides.pop("cweid", "-1"),
        "instances": overrides.pop(
            "instances",
            [
                {
                    "id": "1",
                    "uri": "http://test.local/item?name=payload",
                    "method": "GET",
                    "param": "name",
                    "attack": "scanner-payload",
                    "evidence": "scanner-evidence",
                    "request-header": (
                        "GET http://test.local/item?name=payload HTTP/1.1\r\n"
                        "Host: test.local\r\n\r\n"
                    ),
                    "request-body": "",
                    "response-header": (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/html\r\n\r\n"
                    ),
                    "response-body": "ok",
                }
            ],
        ),
        **overrides,
    }
    return alert


def make_report_with_alerts(alerts):
    report = {
        "@programName": "ZAP",
        "@version": "2.17.0",
        "created": "2026-08-16T00:00:00Z",
        "site": [
            {
                "@name": "http://test.local",
                "alerts": alerts,
            }
        ],
    }
    return json.dumps(report).encode("utf-8")


def test_xss_plugin_accepted_and_normalized():
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(XSS_ZAP_REPORT),
        scan_id="scan-xss-001",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.source.scanner == "ZAP"
    assert finding.source.scanner_finding_id == "40012"

    assert finding.vulnerability.category == "XSS"
    assert finding.vulnerability.subtype == "REFLECTED"
    assert finding.vulnerability.cwe == "CWE-79"

    assert finding.target.parameter == "name"
    assert finding.target.parameter_location == "QUERY"

    assert (
        finding.original_test.payload
        == "<script>alert(1)</script>"
    )
    assert (
        finding.original_test.evidence
        == "<script>alert(1)</script>"
    )

    assert finding.request.headers.get("host") == "127.0.0.1"
    assert finding.request.raw is not None

    assert finding.response is not None
    assert finding.response.status_code == 200
    assert "alert(1)" in finding.response.body


def test_sqli_regression_still_sqli():
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(SQLI_ZAP_REPORT),
        scan_id="scan-sqli-regress",
    )

    assert len(findings) == 1
    assert findings[0].vulnerability.category == "SQLI"
    assert findings[0].vulnerability.subtype is None
    assert findings[0].vulnerability.cwe == "CWE-89"


def test_mixed_report_produces_xss_and_sqli_findings():
    parser = ZapParser()

    alerts = [
        make_alert("40012", "Cross Site Scripting (Reflected)", cweid="79"),
        make_alert("40018", "SQL Injection - MySQL", cweid="89"),
    ]

    findings = parser.parse(
        content=make_report_with_alerts(alerts),
        scan_id="scan-mixed-001",
    )

    assert len(findings) == 2

    categories = {f.vulnerability.category for f in findings}
    assert categories == {"XSS", "SQLI"}


def test_unsupported_plugin_ignored():
    parser = ZapParser()

    alerts = [
        make_alert("99999", "Some Unsupported Alert"),
    ]

    findings = parser.parse(
        content=make_report_with_alerts(alerts),
        scan_id="scan-unsupported-001",
    )

    assert findings == []


def test_no_fuzzy_xss_classification_from_description():
    parser = ZapParser()

    alerts = [
        make_alert(
            "10031",
            "User Controllable HTML Element Attribute (Potential XSS)",
        ),
    ]

    findings = parser.parse(
        content=make_report_with_alerts(alerts),
        scan_id="scan-fuzzy-001",
    )

    assert findings == []


def test_exact_alert_name_fallback_maps_to_40012():
    parser = ZapParser()

    alert = make_alert("", "Cross Site Scripting (Reflected)", cweid="79")
    alert["pluginid"] = ""

    findings = parser.parse(
        content=make_report_with_alerts([alert]),
        scan_id="scan-fallback-001",
    )

    assert len(findings) == 1
    assert findings[0].vulnerability.category == "XSS"
    assert findings[0].vulnerability.subtype == "REFLECTED"


def test_xss_missing_cwe_defaults_to_cwe_79():
    parser = ZapParser()

    alert = make_alert(
        "40012", "Cross Site Scripting (Reflected)", cweid="-1"
    )

    findings = parser.parse(
        content=make_report_with_alerts([alert]),
        scan_id="scan-xss-cwe-001",
    )

    assert findings[0].vulnerability.cwe == "CWE-79"


def test_sqli_missing_cwe_still_defaults_to_cwe_89():
    parser = ZapParser()

    alert = make_alert(
        "40018", "SQL Injection - MySQL", cweid="-1"
    )

    findings = parser.parse(
        content=make_report_with_alerts([alert]),
        scan_id="scan-sqli-cwe-001",
    )

    assert findings[0].vulnerability.cwe == "CWE-89"