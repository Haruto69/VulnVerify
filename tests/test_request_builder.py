from backend.models.normalized_finding import NormalizedFinding
from backend.replay.request_builder import build_replay_request


def make_finding() -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-001",
        finding_id="finding-001",

        source={
            "scanner": "ZAP",
            "scanner_finding_id": "40018",
            "original_name": "SQL Injection - MySQL",
        },

        vulnerability={
            "category": "SQLI",
            "subtype": None,
            "raw_severity": "High (Medium)",
            "normalized_severity": "HIGH",
            "raw_confidence": "2",
            "normalized_confidence": "UNKNOWN",
            "cwe": "CWE-89",
        },

        target={
            "url": (
                "http://127.0.0.1/"
                "DVWA/vulnerabilities/sqli/"
                "?id=%27&Submit=Submit"
            ),
            "normalized_url": (
                "http://127.0.0.1/"
                "DVWA/vulnerabilities/sqli/"
            ),
            "host": "127.0.0.1",
            "path": "/DVWA/vulnerabilities/sqli/",
            "parameter": "id",
            "parameter_location": "QUERY",
        },

        original_test={
            "payload": "'",
            "evidence": (
                "You have an error in your SQL syntax"
            ),
        },

        request={
            "method": "GET",
            "url": (
                "http://127.0.0.1/"
                "DVWA/vulnerabilities/sqli/"
                "?id=%27&Submit=Submit"
            ),
            "path": "/DVWA/vulnerabilities/sqli/",
            "query_parameters": {
                "id": ["'"],
                "Submit": ["Submit"],
            },
            "headers": {
                "host": "127.0.0.1",
                "cookie": (
                    "security=low; "
                    "PHPSESSID=test-session"
                ),
                "accept": "text/html",
            },
            "cookies": {
                "security": "low",
                "PHPSESSID": "test-session",
            },
            "body": None,
            "content_type": None,
            "raw": None,
        },

        response={
            "status_code": 200,
            "headers": {
                "content-type": "text/html"
            },
            "cookies": {},
            "body": "response body",
            "raw": None,
            "response_time_ms": None,
        },

        context={
            "authentication_required": "UNKNOWN",
            "session_required": "UNKNOWN",
        },

        references=[],
        metadata={},
    )


def test_builds_replay_request_from_normalized_finding():
    finding = make_finding()

    replay_request = build_replay_request(
        finding
    )

    assert replay_request.method == "GET"

    assert replay_request.url == (
        "http://127.0.0.1/"
        "DVWA/vulnerabilities/sqli/"
        "?id=%27&Submit=Submit"
    )

    assert replay_request.headers["host"] == (
        "127.0.0.1"
    )

    assert replay_request.headers["cookie"] == (
        "security=low; "
        "PHPSESSID=test-session"
    )

    assert replay_request.body is None


def test_builder_does_not_modify_normalized_request():
    finding = make_finding()

    original_headers = dict(
        finding.request.headers
    )

    replay_request = build_replay_request(
        finding
    )

    replay_request.headers[
        "x-test-header"
    ] = "changed"

    assert (
        finding.request.headers
        == original_headers
    )

    assert (
        "x-test-header"
        not in finding.request.headers
    )