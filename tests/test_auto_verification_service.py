"""
Tests for backend/services/auto_verification_service.py -- automatic
verification orchestration run after a fresh scan upload.

Conventions follow the existing test suite: TestClient(app) is not
used here (these are direct, service-level tests of
run_auto_verification/build_auto_trigger themselves); monkeypatches
target the exact call sites already established by
tests/test_sqli_error_based_endpoint.py, tests/test_csrf_har_
integration.py, and tests/test_zap_xss_end_to_end.py
(backend.api.findings.collect_error_based_replay_evidence,
backend.api.findings.replay_finding,
backend.api.findings.replay_with_cross_site_origin,
backend.replay.xss.execute_replay), since run_auto_verification
dispatches to the exact same, unmodified per-family functions those
tests already exercise.
"""

import json
from datetime import datetime, timezone

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
from backend.models.replay_result import (
    ReplayExecution,
    ReplayRequest,
    ReplayResponse,
    ReplayResult,
)
from backend.parsers.zap_har import parse_har_report
from backend.replay.csrf import CsrfOriginReplayResult, CsrfOriginMutation
from backend.services.auto_verification_service import (
    build_auto_trigger,
    run_auto_verification,
)
from backend.services.scan_service import (
    save_normalized_findings,
)
from backend.storage.repository import (
    auto_verification_queued_scan_ids,
    normalized_findings,
    scans,
    verification_progress,
    verified_findings,
)


HAR_CSRF_REPORT = "tests/fixtures/zap/zap_dvwa_csrf.json"


def reset_storage():
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()
    verification_progress.clear()
    auto_verification_queued_scan_ids.clear()


def make_sqli_finding(
    scan_id: str = "scan-auto-001",
    finding_id: str = "sqli-auto-001",
) -> NormalizedFinding:
    url = "http://127.0.0.1/DVWA/vulnerabilities/sqli/?id=%27&Submit=Submit"

    return NormalizedFinding(
        scan_id=scan_id,
        finding_id=finding_id,
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
        original_test=OriginalTest(
            payload="'",
            evidence="You have an error in your SQL syntax",
        ),
        request=HttpRequest(
            method="GET",
            url=url,
            path="/DVWA/vulnerabilities/sqli/",
        ),
    )


def make_xss_finding(
    scan_id: str = "scan-auto-001",
    finding_id: str = "xss-auto-001",
) -> NormalizedFinding:
    url = "http://127.0.0.1/DVWA/vulnerabilities/xss_r/?name=placeholder"

    return NormalizedFinding(
        scan_id=scan_id,
        finding_id=finding_id,
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
        ),
    )


def make_unsupported_family_finding(
    scan_id: str = "scan-auto-001",
    finding_id: str = "cors-auto-001",
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id=scan_id,
        finding_id=finding_id,
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="99999",
            original_name="CORS Misconfiguration",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.CORS,
            subtype=None,
            raw_severity="Medium",
            normalized_severity=NormalizedSeverity.MEDIUM,
            raw_confidence="Medium",
            normalized_confidence=NormalizedConfidence.MEDIUM,
            cwe=None,
        ),
        target=TargetInfo(
            url="http://127.0.0.1/api/data",
            normalized_url="http://127.0.0.1/api/data",
            host="127.0.0.1",
            path="/api/data",
            parameter=None,
            parameter_location=ParameterLocation.UNKNOWN,
        ),
        original_test=OriginalTest(payload=None, evidence=None),
        request=HttpRequest(
            method="GET",
            url="http://127.0.0.1/api/data",
            path="/api/data",
        ),
    )


def real_dvwa_csrf_finding() -> NormalizedFinding:
    with open(HAR_CSRF_REPORT, encoding="utf-8") as f:
        report = json.load(f)

    return parse_har_report(report, scan_id="scan-auto-001")[0]


# ---------------------------------------------------------------------
# 1/2/3/4. build_auto_trigger: correct trigger per supported family,
# None for an unsupported family.
# ---------------------------------------------------------------------


def test_sqli_finding_automatically_gets_error_based_trigger():
    trigger = build_auto_trigger(make_sqli_finding())

    assert trigger is not None
    assert trigger.sqli is not None
    assert trigger.sqli.error_based is not None
    assert trigger.sqli.time_based is None
    assert trigger.csrf is None
    assert trigger.xss is None


def test_csrf_finding_automatically_gets_password_changed_and_origin_referer():
    trigger = build_auto_trigger(real_dvwa_csrf_finding())

    assert trigger is not None
    assert trigger.csrf is not None

    # Exact string, no extra whitespace.
    assert (
        trigger.csrf.state_check.deterministic_acceptance_indicator
        == "Password Changed."
    )

    assert trigger.csrf.origin_test is not None
    assert trigger.csrf.origin_test.mutation == CsrfOriginMutation.BOTH

    # defense_test (known token/header removal) is not auto-enabled --
    # it isn't part of the working manual default either, and there is
    # no known token field to test on a tokenless HAR-derived form.
    assert trigger.csrf.defense_test is None


def test_xss_finding_automatically_gets_exactly_two_default_payloads():
    trigger = build_auto_trigger(make_xss_finding())

    assert trigger is not None
    assert trigger.xss is not None

    variants = trigger.xss.reflected.payload_variants
    assert len(variants) == 2

    payloads = {variant.payload for variant in variants}
    assert payloads == {
        '<script>alert("hello")</script>',
        '<script>alert("xss")</script>',
    }


def test_unsupported_vulnerability_family_is_not_automatically_verified():
    trigger = build_auto_trigger(make_unsupported_family_finding())

    assert trigger is None


# ---------------------------------------------------------------------
# 6. Automatic verification stores the same classification the
# underlying, unmodified verification function itself produces.
# ---------------------------------------------------------------------


def test_run_auto_verification_stores_sqli_true_positive(monkeypatch):
    reset_storage()

    scan_id = "scan-auto-001"
    finding = make_sqli_finding(scan_id=scan_id)
    save_normalized_findings(scan_id=scan_id, findings=[finding])

    clean_body = "<html><body>ID: 1<br>First name: admin</body></html>"
    error_body = (
        "Fatal error ... mysqli_sql_exception: You have an error in "
        "your SQL syntax; check the manual..."
    )

    def replay(body, status=200):
        return ReplayResult(
            finding_id=finding.finding_id,
            replay=ReplayExecution(
                executed=True,
                timestamp=datetime.now(timezone.utc),
                request=ReplayRequest(
                    method="GET",
                    url=finding.target.url,
                    headers={},
                    body=None,
                ),
                response=ReplayResponse(
                    status=status, headers={}, body=body
                ),
            ),
            observations=[],
            errors=[],
        )

    def fake_collect_error_based_replay_evidence(**kwargs):
        from backend.replay.sqli_error_based_collector import (
            SqliErrorBasedReplayEvidence,
        )

        request = ReplayRequest(
            method="GET",
            url=finding.target.url,
            headers={},
            body=None,
        )

        return SqliErrorBasedReplayEvidence(
            baseline_request=request,
            verification_request=request,
            baseline_replays=(
                replay(clean_body),
                replay(clean_body),
                replay(clean_body),
            ),
            verification_replays=(
                replay(error_body),
                replay(error_body),
                replay(error_body),
            ),
        )

    monkeypatch.setattr(
        "backend.api.findings.collect_error_based_replay_evidence",
        fake_collect_error_based_replay_evidence,
    )

    run_auto_verification(scan_id)

    verified = verified_findings[scan_id][finding.finding_id]
    assert verified.classification.status == "TRUE_POSITIVE"

    progress = verification_progress[scan_id]
    assert progress["status"] == "COMPLETED"
    assert progress["total"] == 1
    assert progress["completed"] == 1
    assert progress["counts"]["TRUE_POSITIVE"] == 1


def test_run_auto_verification_reaches_csrf_true_positive(monkeypatch):
    reset_storage()

    scan_id = "scan-auto-001"
    finding = real_dvwa_csrf_finding()
    finding = finding.model_copy(update={"scan_id": scan_id})
    save_normalized_findings(scan_id=scan_id, findings=[finding])

    def matching_replay(**_kwargs):
        return ReplayResult(
            finding_id=finding.finding_id,
            replay=ReplayExecution(
                executed=True,
                timestamp=datetime.now(timezone.utc),
                request=ReplayRequest(
                    method="GET",
                    url=finding.request.url,
                    headers={},
                    body=None,
                ),
                response=ReplayResponse(
                    status=200,
                    headers={},
                    body="<pre>Password Changed.</pre>",
                ),
            ),
            observations=[],
            errors=[],
        )

    def fake_origin_replay(
        finding_id, request, mutation, timeout_seconds
    ):
        baseline = matching_replay()
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
        "backend.api.findings.replay_finding",
        matching_replay,
    )
    monkeypatch.setattr(
        "backend.api.findings.replay_with_cross_site_origin",
        fake_origin_replay,
    )

    run_auto_verification(scan_id)

    verified = verified_findings[scan_id][finding.finding_id]
    assert verified.classification.status == "TRUE_POSITIVE"


def test_run_auto_verification_reaches_xss_true_positive(monkeypatch):
    reset_storage()

    scan_id = "scan-auto-001"
    finding = make_xss_finding(scan_id=scan_id)
    save_normalized_findings(scan_id=scan_id, findings=[finding])

    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        from urllib.parse import unquote

        decoded_url = unquote(request.url)
        payload = (
            '<script>alert("hello")</script>'
            if 'alert("hello")' in decoded_url
            else '<script>alert("xss")</script>'
        )
        body = f"<div>{payload}</div>"

        return ReplayResult(
            finding_id=finding_id,
            replay=ReplayExecution(
                executed=True,
                timestamp=datetime.now(timezone.utc),
                request=ReplayRequest(
                    method="GET",
                    url=request.url,
                    headers={},
                    body=None,
                ),
                response=ReplayResponse(
                    status=200, headers={}, body=body
                ),
            ),
            observations=[],
            errors=[],
        )

    monkeypatch.setattr(
        "backend.replay.xss.execute_replay",
        fake_execute_replay,
    )

    run_auto_verification(scan_id)

    verified = verified_findings[scan_id][finding.finding_id]
    assert verified.classification.status == "TRUE_POSITIVE"


# ---------------------------------------------------------------------
# 7. Stale CSRF session remains INCONCLUSIVE, never FALSE_POSITIVE.
# ---------------------------------------------------------------------


def test_run_auto_verification_stale_csrf_session_is_inconclusive(
    monkeypatch,
):
    reset_storage()

    scan_id = "scan-auto-001"
    finding = real_dvwa_csrf_finding()
    finding = finding.model_copy(update={"scan_id": scan_id})
    save_normalized_findings(scan_id=scan_id, findings=[finding])

    def redirect_replay(**_kwargs):
        return ReplayResult(
            finding_id=finding.finding_id,
            replay=ReplayExecution(
                executed=True,
                timestamp=datetime.now(timezone.utc),
                request=ReplayRequest(
                    method="GET",
                    url=finding.request.url,
                    headers={},
                    body=None,
                ),
                response=ReplayResponse(
                    status=302,
                    headers={"location": "/DVWA/login.php"},
                    body=None,
                ),
            ),
            observations=[],
            errors=[],
        )

    monkeypatch.setattr(
        "backend.api.findings.replay_finding",
        redirect_replay,
    )

    run_auto_verification(scan_id)

    verified = verified_findings[scan_id][finding.finding_id]
    assert verified.classification.status == "INCONCLUSIVE"
    assert verified.classification.status != "FALSE_POSITIVE"

    progress = verification_progress[scan_id]
    assert progress["counts"]["INCONCLUSIVE"] == 1


# ---------------------------------------------------------------------
# 5/11. An already-verified finding is never re-verified automatically.
# ---------------------------------------------------------------------


def test_already_verified_finding_is_not_reverified(monkeypatch):
    reset_storage()

    scan_id = "scan-auto-001"
    finding = make_sqli_finding(scan_id=scan_id)
    save_normalized_findings(scan_id=scan_id, findings=[finding])

    from backend.models.verified_finding import VerifiedFinding

    pre_existing = VerifiedFinding(
        finding_id=finding.finding_id,
        classification={
            "status": "FALSE_POSITIVE",
            "confidence": 0.9,
            "reason": "manually verified earlier",
        },
        evidence={
            "indicators": [],
            "request_reference": None,
            "response_reference": None,
        },
        verification_method="sqli_error_based_rule_v1",
    )
    verified_findings[scan_id] = {
        finding.finding_id: pre_existing
    }

    called = {"count": 0}

    def fake_collect_error_based_replay_evidence(**kwargs):
        # Tracked via a counter, not a raised exception: exceptions
        # from one finding's verification are intentionally caught
        # and logged by run_auto_verification (see PART 13 error
        # handling), so a raise here would be silently swallowed
        # rather than failing the test.
        called["count"] += 1
        raise RuntimeError("unreachable")

    monkeypatch.setattr(
        "backend.api.findings.collect_error_based_replay_evidence",
        fake_collect_error_based_replay_evidence,
    )

    run_auto_verification(scan_id)

    assert called["count"] == 0
    # The pre-existing manual result is untouched. Compared by value
    # (== ), not identity (is): verified_findings is now backed by
    # SQLite (see backend/storage/collections.py), so a read always
    # returns a freshly-deserialized VerifiedFinding, never the exact
    # object that was written -- "untouched" means the stored data is
    # unchanged, not that a Python object survived, which was never
    # a real product guarantee.
    assert (
        verified_findings[scan_id][finding.finding_id]
        == pre_existing
    )

    progress = verification_progress[scan_id]
    assert progress["total"] == 0
    assert progress["status"] == "COMPLETED"


# ---------------------------------------------------------------------
# Scan-level dedup: calling run_auto_verification twice for the same
# scan only actually runs once.
# ---------------------------------------------------------------------


def test_run_auto_verification_only_runs_once_per_scan(monkeypatch):
    reset_storage()

    scan_id = "scan-auto-001"
    finding = make_sqli_finding(scan_id=scan_id)
    save_normalized_findings(scan_id=scan_id, findings=[finding])

    call_count = {"n": 0}

    def fake_collect_error_based_replay_evidence(**kwargs):
        call_count["n"] += 1
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "backend.api.findings.collect_error_based_replay_evidence",
        fake_collect_error_based_replay_evidence,
    )

    run_auto_verification(scan_id)
    first_call_count = call_count["n"]

    run_auto_verification(scan_id)
    second_call_count = call_count["n"]

    assert first_call_count == second_call_count


# ---------------------------------------------------------------------
# Wiring: a fresh scan upload dispatches automatic verification (via a
# detached thread, synchronously stood in here so the test can observe
# the outcome deterministically) and the progress endpoint reports it.
# ---------------------------------------------------------------------


def test_upload_dispatches_automatic_verification(monkeypatch):
    from fastapi.testclient import TestClient

    from backend.main import app

    reset_storage()

    client = TestClient(app)

    class SynchronousThread:
        """
        Stands in for threading.Thread in backend/api/scans.py so this
        test can assert on the outcome without racing a real
        background thread -- runs the target function immediately and
        synchronously instead of on a separate OS thread.
        """

        def __init__(self, target, args=(), daemon=None):
            self._target = target
            self._args = args

        def start(self):
            self._target(*self._args)

    monkeypatch.setattr(
        "backend.api.scans.threading.Thread",
        SynchronousThread,
    )

    def fake_collect_error_based_replay_evidence(**kwargs):
        from backend.replay.sqli_error_based_collector import (
            SqliErrorBasedReplayEvidence,
        )

        request = ReplayRequest(
            method="GET",
            url="http://127.0.0.1/DVWA/vulnerabilities/sqli/",
            headers={},
            body=None,
        )
        clean = ReplayResult(
            finding_id="placeholder",
            replay=ReplayExecution(
                executed=True,
                timestamp=datetime.now(timezone.utc),
                request=request,
                response=ReplayResponse(
                    status=200, headers={}, body="clean"
                ),
            ),
            observations=[],
            errors=[],
        )
        error = ReplayResult(
            finding_id="placeholder",
            replay=ReplayExecution(
                executed=True,
                timestamp=datetime.now(timezone.utc),
                request=request,
                response=ReplayResponse(
                    status=200,
                    headers={},
                    body=(
                        "You have an error in your SQL syntax"
                    ),
                ),
            ),
            observations=[],
            errors=[],
        )

        return SqliErrorBasedReplayEvidence(
            baseline_request=request,
            verification_request=request,
            baseline_replays=(clean, clean, clean),
            verification_replays=(error, error, error),
        )

    monkeypatch.setattr(
        "backend.api.findings.collect_error_based_replay_evidence",
        fake_collect_error_based_replay_evidence,
    )

    with open(
        "tests/fixtures/zap/zap_sqli_positive.json", "rb"
    ) as f:
        response = client.post(
            "/api/v1/scans",
            data={"scanner": "ZAP"},
            files={
                "file": (
                    "zap_sqli_positive.json",
                    f,
                    "application/json",
                )
            },
        )

    assert response.status_code == 200
    scan_id = response.json()["scan_id"]

    progress_response = client.get(
        f"/api/v1/scans/{scan_id}/verification-progress"
    )
    assert progress_response.status_code == 200
    progress = progress_response.json()

    assert progress["status"] == "COMPLETED"
    assert progress["total"] == 1
    assert progress["counts"]["TRUE_POSITIVE"] == 1

    verified_response = client.get(
        f"/api/v1/scans/{scan_id}/verified-findings"
    )
    assert verified_response.json()["count"] == 1
    assert (
        verified_response.json()["findings"][0]["classification"][
            "status"
        ]
        == "TRUE_POSITIVE"
    )


def test_verification_progress_not_started_for_unknown_progress():
    from fastapi.testclient import TestClient

    from backend.main import app

    reset_storage()

    client = TestClient(app)

    scans["scan-no-progress"] = {
        "scan_id": "scan-no-progress",
        "filename": "x.json",
        "content_type": "application/json",
        "scanner": "ZAP",
        "status": "NORMALIZED",
        "error": None,
    }

    response = client.get(
        "/api/v1/scans/scan-no-progress/verification-progress"
    )

    assert response.status_code == 200
    assert response.json()["status"] == "NOT_STARTED"
