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


# ---------------------------------------------------------------------
# ZAP reflected XSS (pluginid 40012) is no longer discarded by the
# formerly SQLi-only _is_supported_alert/_classify_alert path, and is
# normalized correctly rather than mislabeled SQLI/CWE-89.
# ---------------------------------------------------------------------


def test_normalizes_real_zap_xss_finding():
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(XSS_ZAP_REPORT),
        scan_id="scan-xss-001",
    )

    # a. ZAP reflected XSS is parsed (not discarded).
    assert len(findings) == 1

    finding = findings[0]

    assert finding.scan_id == "scan-xss-001"

    # e. scanner == ZAP.
    assert finding.source.scanner == "ZAP"

    # f. scanner_finding_id == "40012".
    assert finding.source.scanner_finding_id == "40012"

    assert (
        finding.source.original_name
        == "Cross Site Scripting (Reflected)"
    )

    # c. category == XSS.
    assert finding.vulnerability.category == "XSS"

    # d. subtype == the repository's existing reflected-XSS subtype
    # (backend.verification.xss_context.XssSubtype.REFLECTED).
    assert finding.vulnerability.subtype == "REFLECTED"

    # l. severity is normalized correctly (riskcode "3" -> HIGH, same
    # RISK_CODE_MAP the SQLi path already uses).
    assert finding.vulnerability.normalized_severity == "HIGH"

    # m. confidence is preserved (raw), normalized stays UNKNOWN --
    # same policy as the existing SQLi path, not XSS-specific.
    assert finding.vulnerability.raw_confidence == "2"
    assert finding.vulnerability.normalized_confidence == "UNKNOWN"

    # k. CWE is CWE-79 (from ZAP's own cweid, not the SQLi CWE-89
    # fallback).
    assert finding.vulnerability.cwe == "CWE-79"

    assert finding.target.host == "127.0.0.1"
    assert (
        finding.target.path
        == "/DVWA/vulnerabilities/xss_r/"
    )

    # g. parameter is extracted correctly.
    assert finding.target.parameter == "name"

    # h. parameter_location == QUERY for a query parameter.
    assert finding.target.parameter_location == "QUERY"

    # i. original_test.payload is preserved (instance.attack).
    assert (
        finding.original_test.payload
        == "<script>alert(1)</script>"
    )

    # j. original_test.evidence is preserved (instance.evidence).
    assert (
        finding.original_test.evidence
        == "<script>alert(1)</script>"
    )

    assert finding.request.method == "GET"

    assert (
        finding.request.query_parameters["name"]
        == ["<script>alert(1)</script>"]
    )

    assert finding.request.cookies["security"] == "low"
    assert "PHPSESSID" in finding.request.cookies

    # n. request/response fields are handled correctly when present.
    assert finding.response is not None
    assert finding.response.status_code == 200
    assert (
        "<script>alert(1)</script>"
        in finding.response.body
    )

    assert finding.metadata["scan_timestamp"] is not None


def test_xss_alert_not_discarded_by_alert_classification():
    parser = ZapParser()

    content = read_fixture(XSS_ZAP_REPORT)
    report = json.loads(content.decode("utf-8"))

    alert_instances = parser._extract_alert_instances(report)
    alert, _instance = alert_instances[0]

    # b. XSS is not discarded by the alert classification -- the
    # replacement for the old SQLi-only _is_supported_alert.
    classification = parser._classify_alert(alert)

    assert classification is not None
    assert classification.category == "XSS"


def test_xss_finding_with_no_request_response_fields_still_parses():
    """
    A "Traditional JSON" report (no Requests-and-Responses add-on) may
    supply only the basic alert/instance fields, with no
    request-header/request-body/response-header/response-body at all.
    The parser must not raise or silently drop the finding.
    """

    parser = ZapParser()

    content = read_fixture(XSS_ZAP_REPORT)
    report = json.loads(content.decode("utf-8"))

    instance = report["site"][0]["alerts"][0]["instances"][0]

    for key in (
        "request-header",
        "request-body",
        "response-header",
        "response-body",
    ):
        instance.pop(key, None)

    findings = parser._parse_traditional_alerts(
        report=report,
        scan_id="scan-xss-minimal",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.vulnerability.category == "XSS"
    assert finding.request.headers == {}
    assert finding.request.cookies == {}
    assert finding.request.body is None
    assert finding.response is not None
    assert finding.response.status_code == 0
    assert finding.response.body is None


# ---------------------------------------------------------------------
# Regression: the pre-existing SQLi fixture/test keep passing exactly
# as before (see test_normalizes_real_zap_sqli_finding above, already
# unmodified in this file). This test additionally proves SQLi is
# still supported after the classification refactor.
# ---------------------------------------------------------------------


def test_sqli_alert_still_classified_after_refactor():
    parser = ZapParser()

    content = read_fixture(SQLI_ZAP_REPORT)
    report = json.loads(content.decode("utf-8"))

    alert_instances = parser._extract_alert_instances(report)
    sqli_alert = next(
        alert
        for alert, _instance in alert_instances
        if alert.get("pluginid") == "40018"
    )

    classification = parser._classify_alert(sqli_alert)

    assert classification is not None
    assert classification.category == "SQLI"
    assert classification.subtype is None
    assert classification.cwe_fallback == "CWE-89"


# ---------------------------------------------------------------------
# A single ZAP report containing both a SQLi and an XSS alert must
# yield two independently, correctly classified findings -- one alert
# type must never affect the other's classification.
# ---------------------------------------------------------------------


def test_mixed_sqli_and_xss_report_yields_two_correct_findings():
    parser = ZapParser()

    sqli_report = json.loads(
        read_fixture(SQLI_ZAP_REPORT).decode("utf-8")
    )
    xss_report = json.loads(
        read_fixture(XSS_ZAP_REPORT).decode("utf-8")
    )

    sqli_alert = next(
        alert
        for site in sqli_report["site"]
        for alert in site.get("alerts", [])
        if alert.get("pluginid") == "40018"
    )
    xss_alert = xss_report["site"][0]["alerts"][0]

    mixed_report = {
        "@programName": "ZAP",
        "@version": "2.17.0",
        "@generated": "Fri, 14 Aug 2026 16:02:01",
        "created": "2026-08-14T20:02:01.135328980Z",
        "site": [
            {
                "@name": "http://127.0.0.1",
                "@host": "127.0.0.1",
                "@port": "80",
                "@ssl": "false",
                "alerts": [sqli_alert, xss_alert],
            }
        ],
    }

    findings = parser.parse(
        content=json.dumps(mixed_report).encode("utf-8"),
        scan_id="scan-mixed-001",
    )

    assert len(findings) == 2

    categories = {finding.vulnerability.category for finding in findings}
    assert categories == {"SQLI", "XSS"}

    by_category = {
        finding.vulnerability.category: finding
        for finding in findings
    }

    sqli_finding = by_category["SQLI"]
    assert sqli_finding.vulnerability.cwe == "CWE-89"
    assert sqli_finding.vulnerability.subtype is None
    assert sqli_finding.source.scanner_finding_id == "40018"

    xss_finding = by_category["XSS"]
    assert xss_finding.vulnerability.cwe == "CWE-79"
    assert xss_finding.vulnerability.subtype == "REFLECTED"
    assert xss_finding.source.scanner_finding_id == "40012"


def test_unsupported_plugin_id_is_still_discarded():
    # A plugin ID that is neither SQLi nor XSS must still be skipped,
    # exactly like before this refactor -- classification is additive,
    # not "accept everything now".
    parser = ZapParser()

    alert = {
        "pluginid": "99999",
        "alert": "Some Unrelated Alert",
        "name": "Some Unrelated Alert",
        "riskcode": "1",
        "confidence": "1",
    }

    assert parser._classify_alert(alert) is None


def test_alert_description_mentioning_xss_is_not_misclassified():
    # An alert whose description merely mentions "XSS" in passing,
    # under an unsupported/unknown plugin ID and an alert name that
    # does not exactly match the controlled fallback list, must not
    # be classified as XSS by substring matching.
    parser = ZapParser()

    alert = {
        "pluginid": "99998",
        "alert": "Content Security Policy missing (mitigates XSS)",
        "name": "Content Security Policy missing (mitigates XSS)",
        "riskcode": "1",
        "confidence": "1",
    }

    assert parser._classify_alert(alert) is None