"""
Integration tests proving session refresh is correctly threaded
through the real CSRF/SQLi/XSS verification paths and automatic
verification, via the actual /verify HTTP endpoint (TestClient) --
not just the session_refresh module in isolation
(see tests/test_session_refresh.py for those unit tests).

No live target: the login POST and every replay execute_replay call
are mocked, matching every other replay test in this suite.
"""

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.main import app
from backend.models.normalized_finding import (
    FindingContext,
    FindingSource,
    HttpRequest,
    NormalizedConfidence,
    NormalizedFinding,
    NormalizedSeverity,
    OriginalTest,
    ParameterLocation,
    RequirementState,
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
from backend.replay.csrf import CsrfOriginReplayResult
from backend.services.auto_verification_service import (
    run_auto_verification,
)
from backend.services.scan_service import save_normalized_findings
from backend.storage.repository import (
    auto_verification_queued_scan_ids,
    normalized_findings,
    scans,
    verification_progress,
    verified_findings,
)
from tests.test_session_refresh import (
    clear_auth_env,
    install_fake_httpx_client,
    set_dvwa_style_auth_env,
)


client = TestClient(app)

FRESH_COOKIE = "PHPSESSID=fresh-session-9999"
STALE_COOKIE = "PHPSESSID=stale-session-0001"


def reset_storage():
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()
    verification_progress.clear()
    auto_verification_queued_scan_ids.clear()


def setup_scan_with_finding(finding: NormalizedFinding, scan_id: str):
    reset_storage()

    scans[scan_id] = {
        "scan_id": scan_id,
        "filename": "test.json",
        "content_type": "application/json",
        "scanner": "ZAP",
        "status": "NORMALIZED",
        "error": None,
    }
    save_normalized_findings(scan_id=scan_id, findings=[finding])


def make_sqli_finding(scan_id: str) -> NormalizedFinding:
    url = "http://127.0.0.1/DVWA/vulnerabilities/sqli/?id=%27"
    return NormalizedFinding(
        scan_id=scan_id,
        finding_id="sqli-session-001",
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40018",
            original_name="SQL Injection",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.SQLI,
            subtype=None,
            raw_severity="High",
            normalized_severity=NormalizedSeverity.HIGH,
            raw_confidence="Medium",
            normalized_confidence=NormalizedConfidence.MEDIUM,
            cwe="CWE-89",
        ),
        target=TargetInfo(
            url=url,
            normalized_url=(
                "http://127.0.0.1/DVWA/vulnerabilities/sqli/"
            ),
            host="127.0.0.1",
            path="/DVWA/vulnerabilities/sqli/",
            parameter="id",
            parameter_location=ParameterLocation.QUERY,
        ),
        original_test=OriginalTest(payload="'", evidence="SQL error"),
        request=HttpRequest(
            method="GET",
            url=url,
            path="/DVWA/vulnerabilities/sqli/",
            headers={"cookie": STALE_COOKIE},
        ),
        context=FindingContext(
            authentication_required=RequirementState.YES,
            session_required=RequirementState.UNKNOWN,
        ),
    )


def make_csrf_finding(scan_id: str, finding_id: str) -> NormalizedFinding:
    url = (
        "http://127.0.0.1/DVWA/vulnerabilities/csrf/"
        "?password_new=x&password_conf=x&Change=Change"
    )
    return NormalizedFinding(
        scan_id=scan_id,
        finding_id=finding_id,
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40103",
            original_name="Cross Site Request Forgery",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.CSRF,
            subtype=None,
            raw_severity="Medium",
            normalized_severity=NormalizedSeverity.MEDIUM,
            raw_confidence="Medium",
            normalized_confidence=NormalizedConfidence.UNKNOWN,
            cwe="CWE-352",
        ),
        target=TargetInfo(
            url=url,
            normalized_url=(
                "http://127.0.0.1/DVWA/vulnerabilities/csrf/"
            ),
            host="127.0.0.1",
            path="/DVWA/vulnerabilities/csrf/",
            parameter=None,
            parameter_location=ParameterLocation.UNKNOWN,
        ),
        original_test=OriginalTest(payload=None, evidence=None),
        request=HttpRequest(
            method="GET",
            url=url,
            path="/DVWA/vulnerabilities/csrf/",
            headers={"cookie": STALE_COOKIE},
        ),
        context=FindingContext(
            authentication_required=RequirementState.YES,
            session_required=RequirementState.YES,
        ),
    )


def make_xss_finding(scan_id: str) -> NormalizedFinding:
    url = "http://127.0.0.1/DVWA/vulnerabilities/xss_r/?name=placeholder"
    return NormalizedFinding(
        scan_id=scan_id,
        finding_id="xss-session-001",
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40012",
            original_name="Cross Site Scripting (Reflected)",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.XSS,
            subtype="REFLECTED",
            raw_severity="High",
            normalized_severity=NormalizedSeverity.HIGH,
            raw_confidence="Medium",
            normalized_confidence=NormalizedConfidence.UNKNOWN,
            cwe="CWE-79",
        ),
        target=TargetInfo(
            url=url,
            normalized_url=(
                "http://127.0.0.1/DVWA/vulnerabilities/xss_r/"
            ),
            host="127.0.0.1",
            path="/DVWA/vulnerabilities/xss_r/",
            parameter="name",
            parameter_location=ParameterLocation.QUERY,
        ),
        original_test=OriginalTest(
            payload="<script>alert(1)</script>",
            evidence="<script>alert(1)</script>",
        ),
        request=HttpRequest(
            method="GET",
            url=url,
            path="/DVWA/vulnerabilities/xss_r/",
            headers={"cookie": STALE_COOKIE},
        ),
        context=FindingContext(
            authentication_required=RequirementState.YES,
            session_required=RequirementState.UNKNOWN,
        ),
    )


def _replay_capturing_cookie(url: str, status: int, body: str):
    return ReplayResult(
        finding_id="x",
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET", url=url, headers={}, body=None
            ),
            response=ReplayResponse(
                status=status, headers={}, body=body
            ),
        ),
        observations=[],
        errors=[],
    )


# ---------------------------------------------------------------------
# H. SQLi ERROR_BASED verification still works, and uses the refreshed
# session for every baseline/verification replay attempt.
# ---------------------------------------------------------------------


def test_sqli_error_based_uses_refreshed_session(monkeypatch):
    set_dvwa_style_auth_env(monkeypatch)
    install_fake_httpx_client(
        monkeypatch, status_code=302, cookies={"PHPSESSID": "fresh-session-9999"}
    )

    scan_id = "scan-session-sqli"
    finding = make_sqli_finding(scan_id)
    setup_scan_with_finding(finding, scan_id)

    captured_cookies = []

    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        captured_cookies.append(request.headers.get("cookie"))
        return _replay_capturing_cookie(
            request.url, 200, "clean response, no error"
        )

    monkeypatch.setattr(
        "backend.replay.sqli_error_based_collector.execute_replay",
        fake_execute_replay,
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding.finding_id}/verify",
        json={"sqli": {"error_based": {}}},
    )

    assert response.status_code == 200
    assert len(captured_cookies) > 0
    # Every replay attempt used the fresh session, never the stale
    # scanner-captured one.
    assert all(c == FRESH_COOKIE for c in captured_cookies)
    assert STALE_COOKIE not in captured_cookies


# ---------------------------------------------------------------------
# I. CSRF baseline + reproducibility + origin/referer replay all use
# the refreshed session.
# ---------------------------------------------------------------------


def test_csrf_baseline_reproducibility_and_origin_use_refreshed_session(
    monkeypatch,
):
    set_dvwa_style_auth_env(monkeypatch)
    install_fake_httpx_client(
        monkeypatch, status_code=302, cookies={"PHPSESSID": "fresh-session-9999"}
    )

    scan_id = "scan-session-csrf"
    finding = make_csrf_finding(scan_id, "csrf-session-001")
    setup_scan_with_finding(finding, scan_id)

    baseline_cookies = []

    def fake_replay_finding(
        finding, timeout_seconds, session_cookie_override=None
    ):
        baseline_cookies.append(session_cookie_override)
        return _replay_capturing_cookie(
            finding.request.url, 200, "<pre>Password Changed.</pre>"
        )

    origin_cookies = []

    def fake_origin_replay(
        finding_id, request, mutation, timeout_seconds
    ):
        origin_cookies.append(request.headers.get("cookie"))
        baseline = _replay_capturing_cookie(
            request.url, 200, "<pre>Password Changed.</pre>"
        )
        return CsrfOriginReplayResult(
            original_replay=baseline,
            modified_replay=baseline,
            mutation=mutation,
            attacker_origin="https://attacker.example",
            attacker_referer="https://attacker.example/csrf-test",
            rejection_observed=False,
            rejection_status=200,
        )

    monkeypatch.setattr(
        "backend.api.findings.replay_finding", fake_replay_finding
    )
    monkeypatch.setattr(
        "backend.api.findings.replay_with_cross_site_origin",
        fake_origin_replay,
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding.finding_id}/verify",
        json={
            "csrf": {
                "state_check": {
                    "deterministic_acceptance_indicator": (
                        "Password Changed."
                    )
                },
                "origin_test": {"mutation": "BOTH"},
            }
        },
    )

    assert response.status_code == 200

    # baseline + reproducibility replay -- both calls to replay_finding
    # got the same fresh session.
    assert len(baseline_cookies) == 2
    assert all(c == FRESH_COOKIE for c in baseline_cookies)

    # origin/referer replay's base request also carried the fresh
    # session (mutation only replaces Origin/Referer, never Cookie).
    assert len(origin_cookies) == 1
    assert origin_cookies[0] == FRESH_COOKIE


# ---------------------------------------------------------------------
# J. XSS payload variants both use the refreshed session.
# ---------------------------------------------------------------------


def test_xss_variants_use_refreshed_session(monkeypatch):
    set_dvwa_style_auth_env(monkeypatch)
    install_fake_httpx_client(
        monkeypatch, status_code=302, cookies={"PHPSESSID": "fresh-session-9999"}
    )

    scan_id = "scan-session-xss"
    finding = make_xss_finding(scan_id)
    setup_scan_with_finding(finding, scan_id)

    captured_cookies = []

    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        captured_cookies.append(request.headers.get("cookie"))
        return _replay_capturing_cookie(request.url, 200, "<div></div>")

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay", fake_execute_replay
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding.finding_id}/verify",
        json={
            "xss": {
                "reflected": {
                    "payload_variants": [
                        {
                            "variant_id": "v1",
                            "payload": '<script>alert("hello")</script>',
                        },
                        {
                            "variant_id": "v2",
                            "payload": '<script>alert("xss")</script>',
                        },
                    ]
                }
            }
        },
    )

    assert response.status_code == 200
    assert len(captured_cookies) == 2
    assert all(c == FRESH_COOKIE for c in captured_cookies)


# ---------------------------------------------------------------------
# C. Stale session detection is unaffected by session refresh: with
# NO refresh configuration, a 302 baseline replay is still INCONCLUSIVE
# (backend/verification/csrf_context.py::_session_unavailable),
# exactly as before this feature existed.
# ---------------------------------------------------------------------


def test_stale_session_still_inconclusive_when_no_refresh_configured(
    monkeypatch,
):
    clear_auth_env(monkeypatch)

    scan_id = "scan-session-stale"
    finding = make_csrf_finding(scan_id, "csrf-stale-001")
    setup_scan_with_finding(finding, scan_id)

    def redirect_replay(
        finding, timeout_seconds, session_cookie_override=None
    ):
        return _replay_capturing_cookie(
            finding.request.url, 302, None
        )

    monkeypatch.setattr(
        "backend.api.findings.replay_finding", redirect_replay
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding.finding_id}/verify",
        json={
            "csrf": {
                "state_check": {
                    "deterministic_acceptance_indicator": (
                        "Password Changed."
                    )
                }
            }
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["classification"]["status"] == "INCONCLUSIVE"
    assert data["classification"]["status"] != "FALSE_POSITIVE"
    assert data["classification"]["status"] != "TRUE_POSITIVE"


# ---------------------------------------------------------------------
# L. Automatic verification refreshes the session at most once per
# scan and reuses it across multiple findings that need it.
# ---------------------------------------------------------------------


def test_automatic_verification_reuses_session_across_findings(
    monkeypatch,
):
    set_dvwa_style_auth_env(monkeypatch)
    fake_client = install_fake_httpx_client(
        monkeypatch, status_code=302, cookies={"PHPSESSID": "fresh-session-9999"}
    )

    scan_id = "scan-session-auto"
    reset_storage()

    scans[scan_id] = {
        "scan_id": scan_id,
        "filename": "test.json",
        "content_type": "application/json",
        "scanner": "ZAP",
        "status": "NORMALIZED",
        "error": None,
    }

    sqli_finding = make_sqli_finding(scan_id)
    csrf_finding = make_csrf_finding(scan_id, "csrf-auto-session-001")

    save_normalized_findings(
        scan_id=scan_id, findings=[sqli_finding, csrf_finding]
    )

    def fake_error_based_replay(*, finding_id, request, timeout_seconds):
        return _replay_capturing_cookie(
            request.url, 200, "clean response, no error"
        )

    def fake_csrf_replay_finding(
        finding, timeout_seconds, session_cookie_override=None
    ):
        return _replay_capturing_cookie(
            finding.request.url, 200, "<pre>Password Changed.</pre>"
        )

    def fake_origin_replay(
        finding_id, request, mutation, timeout_seconds
    ):
        baseline = _replay_capturing_cookie(
            request.url, 200, "<pre>Password Changed.</pre>"
        )
        return CsrfOriginReplayResult(
            original_replay=baseline,
            modified_replay=baseline,
            mutation=mutation,
            attacker_origin="https://attacker.example",
            attacker_referer="https://attacker.example/csrf-test",
            rejection_observed=False,
            rejection_status=200,
        )

    monkeypatch.setattr(
        "backend.replay.sqli_error_based_collector.execute_replay",
        fake_error_based_replay,
    )
    monkeypatch.setattr(
        "backend.api.findings.replay_finding", fake_csrf_replay_finding
    )
    monkeypatch.setattr(
        "backend.api.findings.replay_with_cross_site_origin",
        fake_origin_replay,
    )

    run_auto_verification(scan_id)

    # Two findings, both requiring authentication -- the login POST
    # must only have happened once, not twice.
    assert len(fake_client.calls) == 1

    progress = verification_progress[scan_id]
    assert progress["status"] == "COMPLETED"
    assert progress["total"] == 2
    assert progress["completed"] == 2
