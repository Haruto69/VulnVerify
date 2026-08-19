"""
Tests for the HAR parsing path added to backend/parsers/zap.py and
implemented in backend/parsers/zap_har.py.

Traditional ZAP alert parsing (backend/parsers/zap.py's original
behavior) is re-verified here to remain unchanged now that dispatch
was added -- these are regression tests over the exact fixtures
tests/test_zap_parser.py already covers, run through the same
ZapParser.parse() entry point post-dispatch.
"""

import json

import pytest

from backend.parsers.zap import ZapParser
from backend.parsers.zap_har import is_har_report, parse_har_report

GENERIC_ZAP_REPORT = "tests/fixtures/zap/zap_report.json"
SQLI_ZAP_REPORT = "tests/fixtures/zap/zap_sqli_positive.json"
HAR_CSRF_REPORT = "tests/fixtures/zap/zap_dvwa_csrf.json"


def read_fixture(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


def load_json(path: str) -> dict:
    return json.loads(read_fixture(path).decode("utf-8"))


# ---------------------------------------------------------------------
# A / N: Traditional ZAP alert parsing is unchanged after dispatch
# was added
# ---------------------------------------------------------------------


def test_traditional_generic_report_still_yields_no_findings():
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(GENERIC_ZAP_REPORT),
        scan_id="scan-test-zap",
    )

    assert findings == []


def test_traditional_sqli_report_still_yields_one_sqli_finding():
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(SQLI_ZAP_REPORT),
        scan_id="scan-sqli-001",
    )

    assert len(findings) == 1
    assert findings[0].vulnerability.category == "SQLI"
    assert findings[0].source.scanner_finding_id == "40018"


def test_invalid_json_still_raises_same_error():
    parser = ZapParser()

    with pytest.raises(ValueError, match="Invalid ZAP JSON report"):
        parser.parse(
            content=b"this is not json",
            scan_id="scan-test-zap",
        )


# ---------------------------------------------------------------------
# C / L: non-HAR, non-Traditional-ZAP JSON is rejected, not silently
# treated as HAR
# ---------------------------------------------------------------------


def test_non_zap_non_har_json_is_rejected():
    parser = ZapParser()

    content = b'{"@programName": "NOT_ZAP", "site": []}'

    with pytest.raises(ValueError, match="not an OWASP ZAP report"):
        parser.parse(content=content, scan_id="scan-test-zap")


def test_arbitrary_json_without_log_or_programname_is_rejected():
    parser = ZapParser()

    content = b'{"some_other_shape": {"nested": true}}'

    with pytest.raises(ValueError, match="not an OWASP ZAP report"):
        parser.parse(content=content, scan_id="scan-test-zap")


def test_is_har_report_requires_log_entries_list():
    assert is_har_report({"log": {"entries": []}}) is True
    assert is_har_report({"log": {"entries": "not-a-list"}}) is False
    assert is_har_report({"log": "not-a-dict"}) is False
    assert is_har_report({"@programName": "ZAP", "site": []}) is False
    assert is_har_report({}) is False


# ---------------------------------------------------------------------
# K: missing/malformed HAR structure produces a clear error
# ---------------------------------------------------------------------


def test_har_missing_log_object_raises_clear_error():
    with pytest.raises(ValueError, match="missing 'log' object"):
        parse_har_report(report={}, scan_id="scan-test")


def test_har_missing_entries_list_raises_clear_error():
    with pytest.raises(ValueError, match="missing 'log.entries' list"):
        parse_har_report(report={"log": {}}, scan_id="scan-test")


def test_har_entry_missing_request_raises_clear_error():
    report = {"log": {"entries": [{"response": {}}]}}

    with pytest.raises(ValueError, match="missing a 'request' object"):
        parse_har_report(report=report, scan_id="scan-test")


# ---------------------------------------------------------------------
# B / D / M: the DVWA CSRF HAR fixture produces exactly one CSRF
# candidate finding, with the expected request shape and provenance
# ---------------------------------------------------------------------


def test_har_csrf_fixture_produces_exactly_one_candidate():
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(HAR_CSRF_REPORT),
        scan_id="scan-csrf-har-001",
    )

    assert len(findings) == 1


def test_har_csrf_finding_category_is_csrf():
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(HAR_CSRF_REPORT),
        scan_id="scan-csrf-har-001",
    )

    assert findings[0].vulnerability.category == "CSRF"


def test_har_csrf_finding_request_shape():
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(HAR_CSRF_REPORT),
        scan_id="scan-csrf-har-001",
    )

    finding = findings[0]

    assert finding.request.method == "GET"
    assert finding.target.path == "/DVWA/vulnerabilities/csrf/"
    assert finding.request.query_parameters["password_new"] == ["meow"]
    assert finding.request.query_parameters["password_conf"] == ["meow"]
    assert finding.request.query_parameters["Change"] == ["Change"]


def test_har_csrf_finding_has_provenance_metadata():
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(HAR_CSRF_REPORT),
        scan_id="scan-csrf-har-001",
    )

    metadata = findings[0].metadata

    assert metadata["csrf_candidate_source"] == "har_form_analysis"
    assert (
        metadata["matched_form_action"]
        == "http://127.0.0.1/DVWA/vulnerabilities/csrf/"
    )
    assert set(metadata["matched_field_names"]) == {
        "password_new",
        "password_conf",
        "Change",
    }


def test_har_csrf_finding_infers_session_required_from_consistent_cookie():
    # The fixture's matched CSRF request carries the same PHPSESSID
    # value as the request that loaded the source form, so this is
    # genuine session-cookie evidence -- session_required should be
    # YES. authentication_required must stay UNKNOWN: a session cookie
    # is not proof of a privileged, logged-in account.
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(HAR_CSRF_REPORT),
        scan_id="scan-csrf-har-001",
    )

    context = findings[0].context

    assert context.session_required == "YES"
    assert context.authentication_required == "UNKNOWN"


def test_har_csrf_finding_preserves_session_cookie_for_replay():
    # The existing replay architecture needs the session cookie to
    # reproduce the request -- it must be preserved even though
    # candidate detection itself never requires or checks for it.
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(HAR_CSRF_REPORT),
        scan_id="scan-csrf-har-001",
    )

    assert (
        findings[0].request.cookies.get("PHPSESSID")
        == "test-session-fake-0001"
    )


def test_har_csrf_finding_does_not_store_response_body():
    # The captured response body is deliberately dropped -- it is not
    # used by CSRF verification and may contain sensitive content.
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(HAR_CSRF_REPORT),
        scan_id="scan-csrf-har-001",
    )

    assert findings[0].response.body is None


def test_har_token_protected_form_does_not_produce_a_second_finding():
    # The fixture also contains a DVWA security.php form protected by
    # a real csrf_token hidden field -- it must not surface as a
    # second finding.
    parser = ZapParser()

    findings = parser.parse(
        content=read_fixture(HAR_CSRF_REPORT),
        scan_id="scan-csrf-har-001",
    )

    urls = [f.target.url for f in findings]

    assert not any("security.php" in url for url in urls)
