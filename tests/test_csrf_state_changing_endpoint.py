"""
Unit tests for backend/api/findings.py::_infer_state_changing_endpoint.

Covers exactly the behavior this task changed:
  - POST/PUT/PATCH/DELETE still unconditionally True (unchanged).
  - An arbitrary GET/HEAD request (no HAR structural corroboration)
    is still None -- GET is never broadly treated as state-changing.
  - A GET/HEAD request that IS a HAR-derived structural CSRF
    candidate (backend/verification/csrf_candidate_detection.py via
    backend/parsers/zap_har.py) is now True.
"""

from backend.api.findings import _infer_state_changing_endpoint
from backend.models.normalized_finding import NormalizedFinding


def make_finding(method: str, metadata: dict | None = None) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-001",
        finding_id="csrf-001",
        source={
            "scanner": "ZAP",
            "scanner_finding_id": None,
            "original_name": "Cross-Site Request Forgery (candidate)",
        },
        vulnerability={
            "category": "CSRF",
            "subtype": None,
            "raw_severity": "Unknown",
            "normalized_severity": "UNKNOWN",
            "raw_confidence": None,
            "normalized_confidence": "UNKNOWN",
            "cwe": "CWE-352",
        },
        target={
            "url": "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            "normalized_url": "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            "host": "127.0.0.1",
            "path": "/DVWA/vulnerabilities/csrf/",
            "parameter": None,
            "parameter_location": "UNKNOWN",
        },
        original_test={"payload": None, "evidence": None},
        request={
            "method": method,
            "url": "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            "path": "/DVWA/vulnerabilities/csrf/",
            "query_parameters": {},
            "headers": {},
            "cookies": {},
            "body": None,
            "content_type": None,
            "raw": None,
        },
        response=None,
        context={
            "authentication_required": "UNKNOWN",
            "session_required": "UNKNOWN",
        },
        references=[],
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------
# Unsafe methods: unchanged, unconditional True
# ---------------------------------------------------------------------


def test_post_is_still_unconditionally_state_changing():
    finding = make_finding("POST")
    assert _infer_state_changing_endpoint(finding) is True


def test_put_patch_delete_are_still_unconditionally_state_changing():
    for method in ("PUT", "PATCH", "DELETE"):
        finding = make_finding(method)
        assert _infer_state_changing_endpoint(finding) is True


# ---------------------------------------------------------------------
# Arbitrary GET/HEAD: still unknown, never broadly True
# ---------------------------------------------------------------------


def test_arbitrary_get_with_no_har_provenance_is_still_unknown():
    finding = make_finding("GET", metadata={})
    assert _infer_state_changing_endpoint(finding) is None


def test_get_with_unrelated_metadata_is_still_unknown():
    finding = make_finding(
        "GET", metadata={"zap_alert_ref": "40103-1"}
    )
    assert _infer_state_changing_endpoint(finding) is None


def test_head_with_no_har_provenance_is_still_unknown():
    finding = make_finding("HEAD", metadata={})
    assert _infer_state_changing_endpoint(finding) is None


# ---------------------------------------------------------------------
# GET with HAR structural candidate provenance: now True
# ---------------------------------------------------------------------


def test_har_derived_get_candidate_is_state_changing():
    finding = make_finding(
        "GET",
        metadata={
            "csrf_candidate_source": "har_form_analysis",
            "matched_form_action": (
                "http://127.0.0.1/DVWA/vulnerabilities/csrf/"
            ),
            "matched_field_names": [
                "password_new",
                "password_conf",
                "Change",
            ],
        },
    )
    assert _infer_state_changing_endpoint(finding) is True


def test_har_derived_post_candidate_is_state_changing_via_method_branch():
    # A HAR-derived POST candidate was already True via the unsafe-
    # method branch before this change; confirm it still is, through
    # either path.
    finding = make_finding(
        "POST",
        metadata={"csrf_candidate_source": "har_form_analysis"},
    )
    assert _infer_state_changing_endpoint(finding) is True
