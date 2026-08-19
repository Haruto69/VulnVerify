"""
End-to-end / verification-safety tests for HAR-derived CSRF
candidates.

Covers:
  O. The existing (unmodified) CSRF verification endpoint accepts a
     HAR-derived CSRF finding without any special-casing.
  P. scanner_related_signal_only is enabled only for the HAR-derived
     candidate, never for an ordinary (e.g. scanner-alert-sourced)
     CSRF finding.
  Q. A HAR-derived candidate cannot become TRUE_POSITIVE merely from
     its own existence -- without independent replay evidence, the
     existing, unmodified classifier still requires every one of its
     deterministic TRUE_POSITIVE conditions, and scanner_related_
     signal_only actively pushes an otherwise-inconclusive case to
     FALSE_POSITIVE instead.
"""

import json
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.api.findings import (
    _derive_defense_absence,
    _forged_request_is_plausible,
    _infer_state_changing_endpoint,
    _is_har_derived_csrf_candidate,
)
from backend.main import app
from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import (
    ReplayExecution,
    ReplayRequest,
    ReplayResponse,
    ReplayResult,
)
from backend.models.verified_finding import VerifiedFinding
from backend.parsers.zap_har import parse_har_report
from backend.replay.csrf import CsrfOriginMutation, CsrfOriginReplayResult
from backend.services.pipeline_service import verify_csrf_finding
from backend.storage.repository import (
    normalized_findings,
    scans,
    verified_findings,
)
from backend.verification.csrf_origin import evaluate_csrf_origin_policy
from backend.verification.csrf_state import (
    CsrfStateObservation,
    has_strong_acceptance_evidence,
)

client = TestClient(app)


HAR_CSRF_REPORT = "tests/fixtures/zap/zap_dvwa_csrf.json"


def read_fixture(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


# ---------------------------------------------------------------------
# P (helper-level): _is_har_derived_csrf_candidate is true only for a
# finding carrying the HAR detector's own provenance marker
# ---------------------------------------------------------------------


def make_finding(metadata: dict) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id="scan-001",
        finding_id="csrf-001",
        source={
            "scanner": "ZAP",
            "scanner_finding_id": "40103",
            "original_name": "Cross Site Request Forgery",
        },
        vulnerability={
            "category": "CSRF",
            "subtype": None,
            "raw_severity": "Medium",
            "normalized_severity": "MEDIUM",
            "raw_confidence": "Medium",
            "normalized_confidence": "UNKNOWN",
            "cwe": "CWE-352",
        },
        target={
            "url": "http://example.test/change",
            "normalized_url": "http://example.test/change",
            "host": "example.test",
            "path": "/change",
            "parameter": None,
            "parameter_location": "UNKNOWN",
        },
        original_test={"payload": None, "evidence": None},
        request={
            "method": "GET",
            "url": "http://example.test/change",
            "path": "/change",
            "query_parameters": {},
            "headers": {},
            "cookies": {},
            "body": None,
            "content_type": None,
            "raw": None,
        },
        response=None,
        context={
            # "YES" here (matching the existing
            # tests/test_csrf_pipeline.py convention) so
            # authenticated_or_privileged_context_required -- derived
            # by backend/verification/csrf_context.py from these two
            # fields, not passed as a direct kwarg -- can be True in
            # the positive TRUE_POSITIVE test below.
            "authentication_required": "YES",
            "session_required": "YES",
        },
        references=[],
        metadata=metadata,
    )


def test_helper_true_for_har_derived_finding():
    finding = make_finding(
        {"csrf_candidate_source": "har_form_analysis"}
    )

    assert _is_har_derived_csrf_candidate(finding) is True


def test_helper_false_for_ordinary_finding_with_no_provenance():
    finding = make_finding({})

    assert _is_har_derived_csrf_candidate(finding) is False


def test_helper_false_for_finding_with_unrelated_metadata():
    finding = make_finding({"zap_alert_ref": "40103-1"})

    assert _is_har_derived_csrf_candidate(finding) is False


# ---------------------------------------------------------------------
# Q (classifier-level): scanner_related_signal_only=True is what the
# HAR path sets, and it must not, on its own, produce TRUE_POSITIVE --
# and it must be able to turn an otherwise-open case into
# FALSE_POSITIVE, exactly like a real scanner-only CSRF signal already
# does for scanner-alert-sourced findings (this exercises the same,
# completely unmodified classifier condition backend/verification/
# csrf.py already had before this feature).
# ---------------------------------------------------------------------


def make_replay(status: int | None = 200) -> ReplayResult:
    return ReplayResult(
        finding_id="csrf-001",
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url="http://example.test/change",
                headers={},
                body=None,
            ),
            response=ReplayResponse(
                status=status,
                headers={},
                body="ok",
            ),
        ),
        observations=[],
        errors=[],
    )


def test_scanner_related_signal_only_prevents_true_positive_alone():
    verified_findings.clear()

    finding = make_finding(
        {"csrf_candidate_source": "har_form_analysis"}
    )

    # No independent replay evidence at all -- an ordinary CSRF
    # finding with this little evidence already resolves to
    # INCONCLUSIVE (see test_csrf_verification_service.py's own
    # test_http_200_still_does_not_create_true_positive). This proves
    # a HAR-derived candidate is no worse off, and specifically never
    # TRUE_POSITIVE, from candidate-detection alone.
    result = verify_csrf_finding(
        finding=finding,
        replay_result=make_replay(status=200),
        state_observation=CsrfStateObservation(),
        scanner_related_signal_only=True,
        verification_confidence=0.20,
    )

    assert result.classification.status != "TRUE_POSITIVE"


def test_scanner_related_signal_only_forces_false_positive_when_open():
    # Construct the one case the existing classifier leaves "open"
    # (no false-positive reason, no true-positive proof either) and
    # show that scanner_related_signal_only=True -- and only that
    # flag -- is what turns it into an explicit FALSE_POSITIVE,
    # exactly matching the classifier's pre-existing, unmodified
    # scanner_related_signal_only branch in
    # backend/verification/csrf.py::_get_false_positive_reason.
    verified_findings.clear()

    finding = make_finding(
        {"csrf_candidate_source": "har_form_analysis"}
    )

    common_kwargs = dict(
        finding=finding,
        replay_result=make_replay(status=200),
        state_observation=CsrfStateObservation(),
        state_changing_endpoint=None,
        verification_confidence=0.30,
    )

    without_flag = verify_csrf_finding(
        scanner_related_signal_only=False,
        **common_kwargs,
    )

    with_flag = verify_csrf_finding(
        scanner_related_signal_only=True,
        **common_kwargs,
    )

    assert without_flag.classification.status == "INCONCLUSIVE"
    assert with_flag.classification.status == "FALSE_POSITIVE"
    assert (
        "does not demonstrate a CSRF vulnerability"
        in with_flag.classification.reason
    )


def test_true_positive_still_requires_every_deterministic_condition():
    # Even with every other TRUE_POSITIVE condition satisfied,
    # scanner_related_signal_only=True still blocks TRUE_POSITIVE --
    # proving the flag is not merely inert. The classifier itself
    # (backend/verification/csrf.py) is completely unmodified; this
    # exercises its pre-existing scanner_related_signal_only branch.
    verified_findings.clear()

    finding = make_finding(
        {"csrf_candidate_source": "har_form_analysis"}
    )

    result = verify_csrf_finding(
        finding=finding,
        replay_result=make_replay(status=200),
        state_observation=CsrfStateObservation(
            before_state_observed=True,
            after_state_observed=True,
            state_changed=True,
        ),
        state_changing_endpoint=True,
        forged_request_is_plausible_under_threat_model=True,
        effective_csrf_defense_absent_or_bypassable=True,
        request_accepted=True,
        reproducible=True,
        evidence_saved=True,
        scanner_related_signal_only=True,
        verification_confidence=0.95,
    )

    assert result.classification.status == "FALSE_POSITIVE"


def test_har_candidate_can_reach_true_positive_with_independent_evidence():
    """
    The corrective half of the fix: scanner_related_signal_only must
    not be a permanent veto. When a HAR-derived candidate's caller
    supplies scanner_related_signal_only=False -- exactly what
    backend/api/findings.py now does once
    has_strong_acceptance_evidence(state_observation) is True -- and
    every other deterministic TRUE_POSITIVE condition is independently
    satisfied, the completely unmodified classifier can reach
    TRUE_POSITIVE. This is the outcome the previous test proved was
    architecturally impossible before this fix.
    """

    verified_findings.clear()

    finding = make_finding(
        {"csrf_candidate_source": "har_form_analysis"}
    )

    result = verify_csrf_finding(
        finding=finding,
        replay_result=make_replay(status=200),
        state_observation=CsrfStateObservation(
            before_state_observed=True,
            after_state_observed=True,
            state_changed=True,
        ),
        state_changing_endpoint=True,
        forged_request_is_plausible_under_threat_model=True,
        effective_csrf_defense_absent_or_bypassable=True,
        request_accepted=True,
        reproducible=True,
        evidence_saved=True,
        scanner_related_signal_only=False,
        verification_confidence=0.95,
    )

    assert result.classification.status == "TRUE_POSITIVE"


# ---------------------------------------------------------------------
# O: the existing, unmodified /verify endpoint accepts a HAR-derived
# CSRF finding end-to-end (upload -> list findings -> verify)
# ---------------------------------------------------------------------


def _upload_har_fixture(scan_id: str = "scan-har-csrf-001") -> str:
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()

    with open(HAR_CSRF_REPORT, "rb") as f:
        response = client.post(
            "/api/v1/scans",
            data={"scanner": "ZAP"},
            files={
                "file": (
                    "zap_dvwa_csrf.json",
                    f,
                    "application/json",
                )
            },
        )

    assert response.status_code == 200
    return response.json()["scan_id"]


def test_upload_produces_one_csrf_finding_via_the_real_endpoint():
    scan_id = _upload_har_fixture()

    response = client.get(f"/api/v1/scans/{scan_id}/findings")

    assert response.status_code == 200
    body = response.json()

    assert body["count"] == 1
    assert body["findings"][0]["vulnerability"]["category"] == "CSRF"


def test_verify_endpoint_accepts_the_har_derived_finding(monkeypatch):
    scan_id = _upload_har_fixture()

    findings_response = client.get(
        f"/api/v1/scans/{scan_id}/findings"
    )
    finding_id = findings_response.json()["findings"][0]["finding_id"]

    monkeypatch.setattr(
        "backend.api.findings.replay_finding",
        lambda **kwargs: make_replay(status=200),
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/verify",
        json={
            "csrf": {
                "state_check": {
                    "deterministic_acceptance_indicator": (
                        "this text never appears in the mocked "
                        "replay body"
                    )
                }
            }
        },
    )

    assert response.status_code == 200

    body = response.json()

    # No independent evidence was supplied (the mocked replay proves
    # nothing), so this must never be TRUE_POSITIVE.
    assert body["classification"]["status"] != "TRUE_POSITIVE"


def test_verify_endpoint_passes_scanner_related_signal_only_for_har_finding(
    monkeypatch,
):
    scan_id = _upload_har_fixture()

    findings_response = client.get(
        f"/api/v1/scans/{scan_id}/findings"
    )
    finding_id = findings_response.json()["findings"][0]["finding_id"]

    monkeypatch.setattr(
        "backend.api.findings.replay_finding",
        lambda **kwargs: make_replay(status=200),
    )

    captured_kwargs = {}

    def capture_and_delegate(**kwargs):
        captured_kwargs.update(kwargs)
        return VerifiedFinding(
            finding_id=finding_id,
            classification={
                "status": "INCONCLUSIVE",
                "confidence": 0.1,
                "reason": "stubbed for test introspection",
            },
            evidence={
                "indicators": [],
                "request_reference": None,
                "response_reference": None,
            },
            verification_method="csrf_rule_v1",
        )

    monkeypatch.setattr(
        "backend.api.findings.verify_csrf_finding",
        capture_and_delegate,
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/verify",
        json={
            "csrf": {
                "state_check": {
                    "deterministic_acceptance_indicator": "irrelevant"
                }
            }
        },
    )

    assert response.status_code == 200
    assert captured_kwargs["scanner_related_signal_only"] is True


def test_matched_indicator_clears_scanner_related_signal_only(
    monkeypatch,
):
    """
    Regression test for the exact bug reported against the live
    DVWA CSRF workflow: once the caller-supplied deterministic
    acceptance indicator actually matches the live replay's response
    body (real, independently observed evidence -- not merely
    supplied text), scanner_related_signal_only must no longer be
    forced True for a HAR-derived candidate. Before this fix,
    csrf.py's classifier would short-circuit to FALSE_POSITIVE
    whenever scanner_related_signal_only was True, regardless of any
    evidence supplied, making TRUE_POSITIVE permanently unreachable
    for any HAR-derived finding.
    """

    scan_id = _upload_har_fixture()

    findings_response = client.get(
        f"/api/v1/scans/{scan_id}/findings"
    )
    finding_id = findings_response.json()["findings"][0]["finding_id"]

    matching_replay = ReplayResult(
        finding_id=finding_id,
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url="http://127.0.0.1/DVWA/vulnerabilities/csrf/",
                headers={},
                body=None,
            ),
            response=ReplayResponse(
                status=200,
                headers={},
                body="Password Changed.",
            ),
        ),
        observations=[],
        errors=[],
    )

    monkeypatch.setattr(
        "backend.api.findings.replay_finding",
        lambda **kwargs: matching_replay,
    )

    captured_kwargs = {}

    def capture_and_delegate(**kwargs):
        captured_kwargs.update(kwargs)
        return VerifiedFinding(
            finding_id=finding_id,
            classification={
                "status": "INCONCLUSIVE",
                "confidence": 0.1,
                "reason": "stubbed for test introspection",
            },
            evidence={
                "indicators": [],
                "request_reference": None,
                "response_reference": None,
            },
            verification_method="csrf_rule_v1",
        )

    monkeypatch.setattr(
        "backend.api.findings.verify_csrf_finding",
        capture_and_delegate,
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/verify",
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
    assert captured_kwargs["scanner_related_signal_only"] is False


# ---------------------------------------------------------------------
# GET-based CSRF verification (backend/api/findings.py::
# _infer_state_changing_endpoint). Unit-level coverage of the
# function itself lives in tests/test_csrf_state_changing_endpoint.py;
# these two exercise it end-to-end.
# ---------------------------------------------------------------------


def test_get_har_candidate_can_reach_true_positive_with_full_evidence():
    """
    Isolated proof that the state_changing_endpoint fix is both
    necessary and sufficient for a GET-method HAR-derived candidate:
    with every other TRUE_POSITIVE condition independently satisfied
    (including an authenticated context and scanner_related_signal_
    only=False, exactly as backend/api/findings.py now computes it
    once strong acceptance evidence exists), a GET finding can now
    reach TRUE_POSITIVE. Mirrors
    test_har_candidate_can_reach_true_positive_with_independent_evidence
    above, but for GET instead of POST -- the only thing this task
    changed.
    """

    verified_findings.clear()

    finding = make_finding(
        {"csrf_candidate_source": "har_form_analysis"}
    )
    finding = finding.model_copy(
        update={
            "request": finding.request.model_copy(
                update={"method": "GET"}
            )
        }
    )

    from backend.api.findings import _infer_state_changing_endpoint

    assert _infer_state_changing_endpoint(finding) is True

    result = verify_csrf_finding(
        finding=finding,
        replay_result=make_replay(status=200),
        state_observation=CsrfStateObservation(
            before_state_observed=True,
            after_state_observed=True,
            state_changed=True,
        ),
        state_changing_endpoint=True,
        forged_request_is_plausible_under_threat_model=True,
        effective_csrf_defense_absent_or_bypassable=True,
        request_accepted=True,
        reproducible=True,
        evidence_saved=True,
        scanner_related_signal_only=False,
        verification_confidence=0.95,
    )

    assert result.classification.status == "TRUE_POSITIVE"


def test_real_dvwa_fixture_get_finding_now_inferred_state_changing(
    monkeypatch,
):
    """
    Runs the actual DVWA CSRF HAR fixture (the real target this task
    is about) end-to-end through the unmodified /verify endpoint and
    confirms state_changing_endpoint=True is now passed for it.

    Also confirms forged_request_is_plausible_under_threat_model=True
    is now passed: the fixture's matched request carries the same
    PHPSESSID cookie value as the request that loaded the source form
    (see CsrfCandidate.session_cookie_consistent in
    backend/verification/csrf_candidate_detection.py), so
    context.session_required is now YES rather than UNKNOWN --
    authentication_required remains UNKNOWN, since a session cookie is
    not proof of a privileged login.

    This still does NOT assert the overall result is TRUE_POSITIVE:
    other independent conditions (e.g. reproducibility, CSRF-defense
    absence corroboration) are not stubbed to true evidence here and
    remain out of scope for this task.
    """

    scan_id = _upload_har_fixture()

    findings_response = client.get(
        f"/api/v1/scans/{scan_id}/findings"
    )
    finding_id = findings_response.json()["findings"][0]["finding_id"]

    assert (
        findings_response.json()["findings"][0]["request"]["method"]
        == "GET"
    )

    monkeypatch.setattr(
        "backend.api.findings.replay_finding",
        lambda **kwargs: make_replay(status=200),
    )

    captured_kwargs = {}

    def capture_and_delegate(**kwargs):
        captured_kwargs.update(kwargs)
        return VerifiedFinding(
            finding_id=finding_id,
            classification={
                "status": "INCONCLUSIVE",
                "confidence": 0.1,
                "reason": "stubbed for test introspection",
            },
            evidence={
                "indicators": [],
                "request_reference": None,
                "response_reference": None,
            },
            verification_method="csrf_rule_v1",
        )

    monkeypatch.setattr(
        "backend.api.findings.verify_csrf_finding",
        capture_and_delegate,
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/verify",
        json={
            "csrf": {
                "state_check": {
                    "deterministic_acceptance_indicator": "irrelevant"
                }
            }
        },
    )

    assert response.status_code == 200
    assert captured_kwargs["state_changing_endpoint"] is True
    assert (
        captured_kwargs["forged_request_is_plausible_under_threat_model"]
        is True
    )


# ---------------------------------------------------------------------
# R: with a matched deterministic acceptance indicator AND independent
# Origin/Referer defense-absence evidence, the real DVWA CSRF HAR
# fixture reaches the existing, unmodified TRUE_POSITIVE rule.
#
# reproducible is supplied directly by the caller here (True), exactly
# as every other TRUE_POSITIVE proof test in this file already does --
# see test_har_candidate_can_reach_true_positive_with_independent_
# evidence above. This test proves the classifier's TRUE_POSITIVE
# rule accepts real evidence in isolation. A separate test further
# below (test_verify_endpoint_reaches_true_positive_end_to_end) proves
# the same outcome is now also reachable through the real, unmodified
# /verify HTTP endpoint, now that
# backend/api/findings.py::_evaluate_csrf_reproducibility replaces the
# previous hardcoded reproducible=None with a real second-replay check.
# ---------------------------------------------------------------------


def _real_dvwa_har_finding() -> NormalizedFinding:
    with open(HAR_CSRF_REPORT, encoding="utf-8") as f:
        report = json.load(f)

    return parse_har_report(report, scan_id="scan-dvwa-csrf")[0]


def test_real_dvwa_fixture_reaches_true_positive_with_defense_and_state_evidence():
    verified_findings.clear()

    finding = _real_dvwa_har_finding()
    assert finding.request.method == "GET"

    replay_result = ReplayResult(
        finding_id=finding.finding_id,
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url=finding.request.url,
                headers=dict(finding.request.headers),
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

    state_observation = CsrfStateObservation(
        deterministic_acceptance_indicator="Password Changed.",
        deterministic_acceptance_indicator_matched=True,
        observation_method="response_indicator",
    )

    # DVWA's Low-security CSRF page enforces no Origin/Referer check
    # at all -- a controlled cross-site replay is accepted, not
    # rejected, which is genuine (unmodified backend/verification/
    # csrf_origin.py) evidence of defense absence.
    origin_observation = evaluate_csrf_origin_policy(
        replay_result=CsrfOriginReplayResult(
            original_replay=replay_result,
            modified_replay=replay_result,
            mutation=CsrfOriginMutation.BOTH,
            attacker_origin="https://attacker.example",
            attacker_referer="https://attacker.example/csrf-test",
            rejection_observed=False,
            rejection_status=200,
        ),
        rejection_attributable_to_origin_policy=False,
    )

    strong_acceptance = has_strong_acceptance_evidence(
        state_observation
    )
    scanner_related_signal_only = (
        _is_har_derived_csrf_candidate(finding)
        and not strong_acceptance
    )

    assert strong_acceptance is True
    assert scanner_related_signal_only is False

    result = verify_csrf_finding(
        finding=finding,
        replay_result=replay_result,
        state_observation=state_observation,
        origin_observation=origin_observation,
        state_changing_endpoint=_infer_state_changing_endpoint(
            finding
        ),
        forged_request_is_plausible_under_threat_model=(
            _forged_request_is_plausible(finding)
        ),
        effective_csrf_defense_absent_or_bypassable=(
            _derive_defense_absence(
                defense_observation=None,
                origin_observation=origin_observation,
            )
        ),
        request_accepted=True,
        reproducible=True,
        evidence_saved=True,
        scanner_related_signal_only=scanner_related_signal_only,
        verification_confidence=0.9,
    )

    assert result.classification.status == "TRUE_POSITIVE"


# ---------------------------------------------------------------------
# S: the new frontend-facing origin_test wiring is actually consumed
# by the real /verify endpoint and reaches
# effective_csrf_defense_absent_or_bypassable=True end-to-end.
# ---------------------------------------------------------------------


def test_verify_endpoint_wires_origin_test_into_defense_absence(
    monkeypatch,
):
    scan_id = _upload_har_fixture()

    findings_response = client.get(
        f"/api/v1/scans/{scan_id}/findings"
    )
    finding_id = findings_response.json()["findings"][0]["finding_id"]

    def fake_replay_finding(**kwargs):
        return make_replay(status=200)

    monkeypatch.setattr(
        "backend.api.findings.replay_finding",
        fake_replay_finding,
    )

    def fake_origin_replay(
        finding_id,
        request,
        mutation,
        timeout_seconds,
    ):
        baseline = make_replay(status=200)
        return CsrfOriginReplayResult(
            original_replay=baseline,
            modified_replay=baseline,
            mutation=mutation,
            attacker_origin="https://attacker.example",
            attacker_referer=None,
            rejection_observed=False,
            rejection_status=200,
        )

    monkeypatch.setattr(
        "backend.api.findings.replay_with_cross_site_origin",
        fake_origin_replay,
    )

    captured_kwargs = {}

    def capture_and_delegate(**kwargs):
        captured_kwargs.update(kwargs)
        return VerifiedFinding(
            finding_id=finding_id,
            classification={
                "status": "INCONCLUSIVE",
                "confidence": 0.1,
                "reason": "stubbed for test introspection",
            },
            evidence={
                "indicators": [],
                "request_reference": None,
                "response_reference": None,
            },
            verification_method="csrf_rule_v1",
        )

    monkeypatch.setattr(
        "backend.api.findings.verify_csrf_finding",
        capture_and_delegate,
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/verify",
        json={
            "csrf": {
                "state_check": {
                    "deterministic_acceptance_indicator": (
                        "Password Changed."
                    )
                },
                "origin_test": {"mutation": "ORIGIN"},
            }
        },
    )

    assert response.status_code == 200
    assert (
        captured_kwargs["effective_csrf_defense_absent_or_bypassable"]
        is True
    )


# ---------------------------------------------------------------------
# T: a stale/expired session on a HAR-derived candidate's baseline
# replay is reported as INCONCLUSIVE, never FALSE_POSITIVE. Before
# this behavior existed, an unmatched indicator alone was enough to
# set scanner_related_signal_only=True and misclassify a stale-session
# replay as FALSE_POSITIVE, even though nothing about the replay
# actually demonstrated the finding was safe.
# ---------------------------------------------------------------------


def test_stale_session_redirect_is_inconclusive_not_false_positive():
    verified_findings.clear()

    finding = _real_dvwa_har_finding()

    # The captured session cookie is no longer valid: DVWA redirects
    # an unauthenticated GET to its login page instead of returning
    # the password-change confirmation.
    replay_result = ReplayResult(
        finding_id=finding.finding_id,
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url=finding.request.url,
                headers=dict(finding.request.headers),
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

    state_observation = CsrfStateObservation(
        deterministic_acceptance_indicator="Password Changed.",
        deterministic_acceptance_indicator_matched=False,
        observation_method="response_indicator",
    )

    scanner_related_signal_only = (
        _is_har_derived_csrf_candidate(finding)
        and not has_strong_acceptance_evidence(state_observation)
    )
    assert scanner_related_signal_only is True

    result = verify_csrf_finding(
        finding=finding,
        replay_result=replay_result,
        state_observation=state_observation,
        state_changing_endpoint=_infer_state_changing_endpoint(
            finding
        ),
        forged_request_is_plausible_under_threat_model=(
            _forged_request_is_plausible(finding)
        ),
        request_accepted=None,
        reproducible=None,
        evidence_saved=True,
        scanner_related_signal_only=scanner_related_signal_only,
        verification_confidence=0.2,
    )

    assert result.classification.status == "INCONCLUSIVE"
    assert (
        "Authentication or session context"
        in result.classification.reason
    )


# ---------------------------------------------------------------------
# U: the real, unmodified /verify HTTP endpoint -- the actual
# frontend/API path, not a direct pipeline_service call -- can now
# reach TRUE_POSITIVE for the real DVWA CSRF HAR fixture. This is the
# concrete proof that backend/api/findings.py no longer hardcodes
# reproducible=None: _evaluate_csrf_reproducibility performs a second,
# independent replay_finding() call (the same replay infrastructure
# used everywhere else), and both attempts agreeing on the matched
# indicator is what supplies reproducible=True here.
# ---------------------------------------------------------------------


def _replay_with(status: int | None, body: str | None) -> ReplayResult:
    return ReplayResult(
        finding_id="csrf-001",
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url="http://127.0.0.1/DVWA/vulnerabilities/csrf/",
                headers={},
                body=None,
            ),
            response=ReplayResponse(
                status=status,
                headers={},
                body=body,
            ),
        ),
        observations=[],
        errors=[],
    )


def _matching_replay(**_kwargs) -> ReplayResult:
    return _replay_with(200, "<pre>Password Changed.</pre>")


def test_verify_endpoint_reaches_true_positive_end_to_end(monkeypatch):
    scan_id = _upload_har_fixture()

    findings_response = client.get(
        f"/api/v1/scans/{scan_id}/findings"
    )
    finding_id = findings_response.json()["findings"][0]["finding_id"]

    monkeypatch.setattr(
        "backend.api.findings.replay_finding",
        _matching_replay,
    )

    def fake_origin_replay(
        finding_id,
        request,
        mutation,
        timeout_seconds,
    ):
        baseline = _matching_replay()
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
        "backend.api.findings.replay_with_cross_site_origin",
        fake_origin_replay,
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/verify",
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
    data = response.json()
    assert data["classification"]["status"] == "TRUE_POSITIVE"


# ---------------------------------------------------------------------
# V: a stale/expired session on the real /verify endpoint (baseline
# replay redirects to a login page) is reported as INCONCLUSIVE, never
# FALSE_POSITIVE -- exercised through the actual HTTP path this time,
# not a direct pipeline_service call.
# ---------------------------------------------------------------------


def test_verify_endpoint_stale_session_is_inconclusive(monkeypatch):
    scan_id = _upload_har_fixture()

    findings_response = client.get(
        f"/api/v1/scans/{scan_id}/findings"
    )
    finding_id = findings_response.json()["findings"][0]["finding_id"]

    def redirect_replay(**_kwargs) -> ReplayResult:
        return _replay_with(302, None)

    monkeypatch.setattr(
        "backend.api.findings.replay_finding",
        redirect_replay,
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/verify",
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


# ---------------------------------------------------------------------
# W: a single successful replay must not, by itself, be treated as
# proof of reproducibility. When a second, independent replay
# disagrees with the first (one matches the indicator, the other
# doesn't), the endpoint must not fabricate reproducible=True or
# guess which attempt was correct -- it reports INCONCLUSIVE via the
# existing (previously unwired) nondeterministic_result flag.
# ---------------------------------------------------------------------


def test_verify_endpoint_disagreeing_replays_do_not_fabricate_reproducibility(
    monkeypatch,
):
    scan_id = _upload_har_fixture()

    findings_response = client.get(
        f"/api/v1/scans/{scan_id}/findings"
    )
    finding_id = findings_response.json()["findings"][0]["finding_id"]

    call_count = {"n": 0}

    def flaky_replay(**_kwargs) -> ReplayResult:
        call_count["n"] += 1

        if call_count["n"] == 1:
            return _replay_with(200, "<pre>Password Changed.</pre>")

        return _replay_with(200, "<pre>Nothing happened.</pre>")

    monkeypatch.setattr(
        "backend.api.findings.replay_finding",
        flaky_replay,
    )

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/verify",
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
    assert call_count["n"] == 2
    assert data["classification"]["status"] != "TRUE_POSITIVE"
    assert data["classification"]["status"] == "INCONCLUSIVE"
    assert (
        "nondeterministic"
        in data["classification"]["reason"].lower()
    )
