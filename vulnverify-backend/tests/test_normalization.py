from pydantic import ValidationError

from backend.models.normalized_finding import NormalizedFinding


def build_valid_finding():
    return {
        "scan_id": "scan-123",
        "finding_id": "finding-123",

        "source": {
            "scanner": "ZAP",
            "scanner_finding_id": "40018",
            "original_name": "SQL Injection"
        },

        "vulnerability": {
            "category": "SQLI",
            "subtype": None,

            "raw_severity": "High",
            "normalized_severity": "HIGH",

            "raw_confidence": "Medium",
            "normalized_confidence": "MEDIUM",

            "cwe": "CWE-89"
        },

        "target": {
            "url": "http://localhost/test?id=1",
            "normalized_url": "http://localhost/test",
            "host": "localhost",
            "path": "/test",

            "parameter": "id",
            "parameter_location": "QUERY"
        },

        "original_test": {
            "payload": "1 OR 1=1",
            "evidence": "SQL syntax difference observed"
        },

        "request": {
            "method": "GET",
            "url": "http://localhost/test?id=1",
            "path": "/test",

            "query_parameters": {
                "id": ["1"]
            },

            "headers": {},
            "cookies": {},

            "body": None,
            "content_type": None,
            "raw": None
        },

        "response": {
            "status_code": 200,
            "headers": {},
            "cookies": {},

            "body": "example response",
            "raw": None,
            "response_time_ms": None
        },

        "context": {
            "authentication_required": "UNKNOWN",
            "session_required": "UNKNOWN"
        },

        "references": [],
        "metadata": {}
    }


def test_valid_normalized_finding():
    finding = NormalizedFinding(**build_valid_finding())

    assert finding.schema_version == "1.0"
    assert finding.vulnerability.category == "SQLI"
    assert finding.target.parameter_location == "QUERY"


def test_invalid_parameter_location():
    data = build_valid_finding()
    data["target"]["parameter_location"] = "URL_PARAM"

    try:
        NormalizedFinding(**data)
        assert False, "Expected validation error"
    except ValidationError:
        assert True


def test_invalid_normalized_severity():
    data = build_valid_finding()
    data["vulnerability"]["normalized_severity"] = "SEVERE"

    try:
        NormalizedFinding(**data)
        assert False, "Expected validation error"
    except ValidationError:
        assert True