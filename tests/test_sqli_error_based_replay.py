"""
Unit tests for backend/replay/sqli_error_based.py (request builder)
and backend/replay/sqli_error_based_collector.py (replay collector),
plus a pipeline-level FALSE_POSITIVE regression test proving
backend.services.pipeline_service.verify_error_based_sqli_finding()
correctly plumbs the existing, unmodified classifier's
controlled-FALSE_POSITIVE path -- exactly mirroring how TIME_BASED's
own pipeline function exposes credible_network_or_server_explanation
as an accepted-but-not-endpoint-derived keyword.
"""

from datetime import datetime, timezone

import pytest

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
from backend.replay.sqli_error_based import (
    build_error_based_replay_requests,
)
from backend.replay.sqli_error_based_collector import (
    collect_error_based_replay_evidence,
)
from backend.services.pipeline_service import (
    verify_error_based_sqli_finding,
)
from backend.storage.repository import (
    verified_findings,
)
from backend.verification.sqli_response import ResponseObservation


def make_sqli_finding(
    *,
    payload: str | None = "'",
    query: str = "id=%27&Submit=Submit",
    finding_id: str = "sqli-error-unit-001",
    scan_id: str = "scan-unit-001",
) -> NormalizedFinding:
    url = f"http://127.0.0.1/DVWA/vulnerabilities/sqli/?{query}"

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
            raw_severity="High (Medium)",
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
            payload=payload,
            evidence="You have an error in your SQL syntax",
        ),
        request=HttpRequest(
            method="GET",
            url=url,
            path="/DVWA/vulnerabilities/sqli/",
        ),
    )


# ---------------------------------------------------------------------
# build_error_based_replay_requests
# ---------------------------------------------------------------------


def test_baseline_strips_scanner_payload_from_current_value():
    finding = make_sqli_finding(
        payload="'",
        query="id=%27&Submit=Submit",
    )

    baseline, verification = build_error_based_replay_requests(
        finding=finding
    )

    # The DVWA/ZAP reference case: current value == payload == "'",
    # so stripping it leaves an empty baseline value.
    assert "id=&Submit=Submit" in baseline.url
    assert "id=%27" in verification.url or "id=" + "'" in (
        verification.url
    )


def test_baseline_clears_value_when_payload_not_present():
    finding = make_sqli_finding(
        payload="1' OR '1'='1",
        query="id=42&Submit=Submit",
    )

    baseline, _ = build_error_based_replay_requests(finding=finding)

    assert "id=&Submit=Submit" in baseline.url


def test_verification_request_is_the_exact_scanner_request():
    finding = make_sqli_finding()

    _, verification = build_error_based_replay_requests(
        finding=finding
    )

    assert verification.url == finding.request.url
    assert verification.method == finding.request.method


def test_non_sqli_finding_is_rejected():
    finding = make_sqli_finding()
    finding = finding.model_copy(
        update={
            "vulnerability": finding.vulnerability.model_copy(
                update={"category": "CSRF"}
            )
        }
    )

    with pytest.raises(ValueError):
        build_error_based_replay_requests(finding=finding)


def test_non_query_parameter_location_is_rejected():
    finding = make_sqli_finding()
    finding = finding.model_copy(
        update={
            "target": finding.target.model_copy(
                update={
                    "parameter_location": ParameterLocation.FORM
                }
            )
        }
    )

    with pytest.raises(ValueError):
        build_error_based_replay_requests(finding=finding)


def test_multiple_occurrences_of_parameter_are_rejected():
    finding = make_sqli_finding(query="id=%27&id=2")

    with pytest.raises(ValueError):
        build_error_based_replay_requests(finding=finding)


# ---------------------------------------------------------------------
# collect_error_based_replay_evidence
# ---------------------------------------------------------------------


def make_replay_result(body, status=200):
    return ReplayResult(
        finding_id="sqli-error-unit-001",
        replay=ReplayExecution(
            executed=True,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url="http://127.0.0.1/DVWA/vulnerabilities/sqli/",
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


def test_collector_stops_verification_early_once_enough_valid_trials(
    monkeypatch,
):
    calls = {"count": 0}

    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        calls["count"] += 1
        return make_replay_result("clean response")

    monkeypatch.setattr(
        "backend.replay.sqli_error_based_collector.execute_replay",
        fake_execute_replay,
    )

    finding = make_sqli_finding()

    evidence = collect_error_based_replay_evidence(finding=finding)

    # profile: baseline_attempts_preferred=3,
    # verification_attempts_min=3 -- with every attempt valid, the
    # collector should stop right at 3 verification attempts rather
    # than running the full max_attempts_per_condition=5.
    assert len(evidence.baseline_replays) == 3
    assert len(evidence.verification_replays) == 3
    assert calls["count"] == 6


def test_collector_derives_response_observations_correctly(
    monkeypatch,
):
    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        return make_replay_result("clean response")

    monkeypatch.setattr(
        "backend.replay.sqli_error_based_collector.execute_replay",
        fake_execute_replay,
    )

    finding = make_sqli_finding()
    evidence = collect_error_based_replay_evidence(finding=finding)

    assert all(
        isinstance(observation, ResponseObservation)
        for observation in evidence.baseline_responses
    )
    assert all(
        observation.valid
        for observation in evidence.verification_responses
    )


def test_collector_marks_connection_failures_invalid(monkeypatch):
    def fake_execute_replay(*, finding_id, request, timeout_seconds):
        return ReplayResult(
            finding_id="sqli-error-unit-001",
            replay=ReplayExecution(
                executed=True,
                timestamp=datetime.now(timezone.utc),
                request=ReplayRequest(
                    method="GET",
                    url="http://127.0.0.1/x",
                    headers={},
                    body=None,
                ),
                response=ReplayResponse(
                    status=None,
                    headers={},
                    body=None,
                ),
            ),
            observations=[],
            errors=["ConnectError: connection refused"],
        )

    monkeypatch.setattr(
        "backend.replay.sqli_error_based_collector.execute_replay",
        fake_execute_replay,
    )

    finding = make_sqli_finding()
    evidence = collect_error_based_replay_evidence(finding=finding)

    # Never reaches the early-exit condition, so the collector should
    # have made the full max_attempts_per_condition=5 attempts.
    assert len(evidence.verification_replays) == 5
    assert all(
        not observation.valid
        for observation in evidence.verification_responses
    )


# ---------------------------------------------------------------------
# Pipeline-level FALSE_POSITIVE (existing classifier path, reused
# unmodified; the API dispatcher does not currently expose this flag,
# exactly mirroring TIME_BASED's own
# credible_network_or_server_explanation precedent)
# ---------------------------------------------------------------------


def test_pipeline_persists_controlled_false_positive():
    verified_findings.clear()

    finding = make_sqli_finding(
        finding_id="sqli-error-fp-001",
        scan_id="scan-fp-001",
    )

    clean = ResponseObservation(
        status_code=200,
        body="<html>ID: 1</html>",
        valid=True,
    )

    verified = verify_error_based_sqli_finding(
        finding=finding,
        baseline_responses=[clean, clean, clean],
        verification_responses=[clean, clean, clean],
        parameter_dependency_established=True,
        controlled_non_sql_explanation_established=True,
    )

    assert verified.classification.status == "FALSE_POSITIVE"
    assert (
        verified_findings["scan-fp-001"][
            "sqli-error-fp-001"
        ].classification.status
        == "FALSE_POSITIVE"
    )


def test_pipeline_rejects_non_sqli_finding():
    finding = make_sqli_finding()
    finding = finding.model_copy(
        update={
            "vulnerability": finding.vulnerability.model_copy(
                update={"category": "XSS"}
            )
        }
    )

    clean = ResponseObservation(
        status_code=200, body="clean", valid=True
    )

    with pytest.raises(ValueError):
        verify_error_based_sqli_finding(
            finding=finding,
            baseline_responses=[clean],
            verification_responses=[clean],
            parameter_dependency_established=True,
        )
