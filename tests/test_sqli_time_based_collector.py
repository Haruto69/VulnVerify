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
from backend.replay.sqli_time_based_collector import (
    collect_time_based_replay_evidence,
)
from backend.verification.sqli_timing import (
    TimingSample,
    TimedReplay,
    VerificationTrialCollection,
)


def make_finding() -> NormalizedFinding:
    attacked_url = (
        "http://test.local/item?"
        "id=1%27+AND+SLEEP%285%29--+"
        "&Submit=Submit"
    )

    return NormalizedFinding(
        scan_id="SCAN-SQLI-COLLECTOR",
        finding_id="F-SQLI-COLLECTOR",
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40018",
            original_name="SQL Injection",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.SQLI,
            subtype="TIME_BASED",
            raw_severity="High",
            normalized_severity=NormalizedSeverity.HIGH,
            raw_confidence="Medium",
            normalized_confidence=NormalizedConfidence.MEDIUM,
            cwe="CWE-89",
        ),
        target=TargetInfo(
            url=attacked_url,
            normalized_url="http://test.local/item",
            host="test.local",
            path="/item",
            parameter="id",
            parameter_location=ParameterLocation.QUERY,
        ),
        original_test=OriginalTest(
            payload="1' AND SLEEP(5)-- ",
            evidence="scanner-evidence",
        ),
        request=HttpRequest(
            method="GET",
            url=attacked_url,
            path="/item",
            headers={
                "cookie": "session=abc123",
                "user-agent": "scanner-agent",
            },
            body=None,
        ),
    )


def make_timed_replay(
    *,
    number: int,
    response_time_ms: float = 100.0,
    status: int | None = 200,
) -> TimedReplay:
    replay_result = ReplayResult(
        finding_id="F-SQLI-COLLECTOR",
        replay=ReplayExecution(
            executed=status is not None,
            timestamp=datetime.now(
                timezone.utc
            ),
            request=ReplayRequest(
                method="GET",
                url="http://test.local/item",
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

    timing_sample = TimingSample(
        request_number=number,
        timestamp=replay_result.replay.timestamp,
        status=status,
        response_time_ms=response_time_ms,
        response_length=2,
        body_fingerprint="test",
        headers={},
        errors=(),
    )

    return TimedReplay(
        sample=timing_sample,
        replay_result=replay_result,
    )


def test_collector_uses_restored_baseline_and_exact_scanner_request(
    monkeypatch,
):
    captured = {}

    def fake_collect_baseline(
        finding_id,
        request,
        count,
        timeout_seconds,
    ):
        captured["baseline_request"] = request

        return [
            make_timed_replay(
                number=index + 1
            )
            for index in range(count)
        ]

    def fake_collect_verification(
        finding_id,
        request,
        profile,
        timeout_seconds,
    ):
        captured["verification_request"] = request

        attempts = tuple(
            make_timed_replay(
                number=index + 1,
                response_time_ms=2500.0,
            )
            for index in range(3)
        )

        return VerificationTrialCollection(
            attempts=attempts,
            valid_trials=attempts,
        )

    monkeypatch.setattr(
        (
            "backend.replay."
            "sqli_time_based_collector."
            "collect_timing_samples"
        ),
        fake_collect_baseline,
    )

    monkeypatch.setattr(
        (
            "backend.replay."
            "sqli_time_based_collector."
            "collect_verification_trials"
        ),
        fake_collect_verification,
    )

    finding = make_finding()

    collect_time_based_replay_evidence(
        finding=finding,
        baseline_parameter_value="1",
    )

    baseline_request = (
        captured["baseline_request"]
    )

    verification_request = (
        captured["verification_request"]
    )

    assert (
        baseline_request.url
        == "http://test.local/item?id=1&Submit=Submit"
    )

    assert (
        verification_request.url
        == finding.request.url
    )

    assert (
        baseline_request.headers
        == finding.request.headers
    )

    assert (
        verification_request.headers
        == finding.request.headers
    )

    assert (
        verification_request.body
        == finding.request.body
    )


def test_collector_uses_preferred_baseline_count_and_time_profile(
    monkeypatch,
):
    captured = {}

    def fake_collect_baseline(
        finding_id,
        request,
        count,
        timeout_seconds,
    ):
        captured["baseline_count"] = count

        return [
            make_timed_replay(
                number=index + 1
            )
            for index in range(count)
        ]

    def fake_collect_verification(
        finding_id,
        request,
        profile,
        timeout_seconds,
    ):
        captured[
            "verification_min"
        ] = profile.verification_attempts_min

        captured[
            "verification_max"
        ] = profile.max_attempts_per_condition

        captured[
            "required_delayed"
        ] = profile.reproduction_required_successes

        attempts = tuple(
            make_timed_replay(
                number=index + 1,
                response_time_ms=2500.0,
            )
            for index in range(3)
        )

        return VerificationTrialCollection(
            attempts=attempts,
            valid_trials=attempts,
        )

    monkeypatch.setattr(
        (
            "backend.replay."
            "sqli_time_based_collector."
            "collect_timing_samples"
        ),
        fake_collect_baseline,
    )

    monkeypatch.setattr(
        (
            "backend.replay."
            "sqli_time_based_collector."
            "collect_verification_trials"
        ),
        fake_collect_verification,
    )

    collect_time_based_replay_evidence(
        finding=make_finding(),
        baseline_parameter_value="1",
    )

    assert captured["baseline_count"] == 7
    assert captured["verification_min"] == 3
    assert captured["verification_max"] == 5
    assert captured["required_delayed"] == 2


def test_collector_preserves_all_attempts_and_valid_trials(
    monkeypatch,
):
    def fake_collect_baseline(
        finding_id,
        request,
        count,
        timeout_seconds,
    ):
        return [
            make_timed_replay(
                number=index + 1
            )
            for index in range(count)
        ]

    def fake_collect_verification(
        finding_id,
        request,
        profile,
        timeout_seconds,
    ):
        attempts = (
            make_timed_replay(
                number=1,
                status=401,
            ),
            make_timed_replay(
                number=2,
                response_time_ms=2500.0,
            ),
            make_timed_replay(
                number=3,
                response_time_ms=2600.0,
            ),
            make_timed_replay(
                number=4,
                response_time_ms=2700.0,
            ),
        )

        valid_trials = (
            attempts[1],
            attempts[2],
            attempts[3],
        )

        return VerificationTrialCollection(
            attempts=attempts,
            valid_trials=valid_trials,
        )

    monkeypatch.setattr(
        (
            "backend.replay."
            "sqli_time_based_collector."
            "collect_timing_samples"
        ),
        fake_collect_baseline,
    )

    monkeypatch.setattr(
        (
            "backend.replay."
            "sqli_time_based_collector."
            "collect_verification_trials"
        ),
        fake_collect_verification,
    )

    evidence = collect_time_based_replay_evidence(
        finding=make_finding(),
        baseline_parameter_value="1",
    )

    assert len(
        evidence.baseline_attempts
    ) == 7

    assert len(
        evidence.baseline_samples
    ) == 7

    assert len(
        evidence.verification_attempts
    ) == 4

    assert len(
        evidence.verification_samples
    ) == 4

    assert len(
        evidence.valid_verification_trials
    ) == 3

    assert len(
        evidence.valid_verification_samples
    ) == 3

    assert (
        evidence.verification_samples[0].status
        == 401
    )


def test_collector_propagates_timeout_to_both_phases(
    monkeypatch,
):
    captured = {}

    def fake_collect_baseline(
        finding_id,
        request,
        count,
        timeout_seconds,
    ):
        captured[
            "baseline_timeout"
        ] = timeout_seconds

        return [
            make_timed_replay(
                number=index + 1
            )
            for index in range(count)
        ]

    def fake_collect_verification(
        finding_id,
        request,
        profile,
        timeout_seconds,
    ):
        captured[
            "verification_timeout"
        ] = timeout_seconds

        attempts = tuple(
            make_timed_replay(
                number=index + 1
            )
            for index in range(3)
        )

        return VerificationTrialCollection(
            attempts=attempts,
            valid_trials=attempts,
        )

    monkeypatch.setattr(
        (
            "backend.replay."
            "sqli_time_based_collector."
            "collect_timing_samples"
        ),
        fake_collect_baseline,
    )

    monkeypatch.setattr(
        (
            "backend.replay."
            "sqli_time_based_collector."
            "collect_verification_trials"
        ),
        fake_collect_verification,
    )

    collect_time_based_replay_evidence(
        finding=make_finding(),
        baseline_parameter_value="1",
        timeout_seconds=12.5,
    )

    assert (
        captured["baseline_timeout"]
        == 12.5
    )

    assert (
        captured["verification_timeout"]
        == 12.5
    )