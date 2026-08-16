from datetime import datetime, timezone

import pytest

from backend.models.replay_result import (
    ReplayExecution,
    ReplayRequest,
    ReplayResponse,
    ReplayResult,
)
from backend.verification.sqli_profiles import (
    SqliSubtype,
    get_sqli_replay_profile,
)
from backend.verification.sqli_timing import (
    TimingSample,
    TimedReplay,
    build_timing_sample,
    collect_timing_samples,
    collect_verification_trials,
    compute_baseline_statistics,
    compute_verification_statistics,
    evaluate_baseline_stability,
    evaluate_trial_delay,
    evaluate_trial_validity,
    execute_timed_replay,
    median,
)


def make_replay_result(
    *,
    status: int | None = 200,
    body: str | None = "ok",
    executed: bool = True,
    errors: list[str] | None = None,
) -> ReplayResult:
    return ReplayResult(
        finding_id="F-SQLI-001",
        replay=ReplayExecution(
            executed=executed,
            timestamp=datetime.now(timezone.utc),
            request=ReplayRequest(
                method="GET",
                url="http://test.local/item?id=1",
                headers={},
                body=None,
            ),
            response=ReplayResponse(
                status=status,
                headers={"Content-Type": "text/html"},
                body=body,
            ),
        ),
        observations=[],
        errors=errors or [],
    )


def make_sample(
    *,
    number: int,
    response_time_ms: float,
    status: int | None = 200,
) -> TimingSample:
    return TimingSample(
        request_number=number,
        timestamp=datetime.now(timezone.utc),
        status=status,
        response_time_ms=response_time_ms,
        response_length=2,
        body_fingerprint="test",
        headers={},
        errors=(),
    )


def test_median_with_odd_count():
    assert median([3.0, 1.0, 2.0]) == 2.0


def test_median_with_even_count():
    assert median([4.0, 1.0, 3.0, 2.0]) == 2.5


def test_median_with_single_value():
    assert median([5.0]) == 5.0


def test_median_with_unsorted_duplicates():
    assert median([8.0, 2.0, 2.0, 9.0, 2.0]) == 2.0


def test_median_with_empty_list_raises():
    with pytest.raises(ValueError):
        median([])


def test_build_timing_sample_from_successful_replay():
    replay = make_replay_result(
        status=200,
        body="hello",
    )

    sample = build_timing_sample(
        request_number=1,
        response_time_ms=125.0,
        replay_result=replay,
    )

    assert sample.request_number == 1
    assert sample.status == 200
    assert sample.response_time_ms == 125.0
    assert sample.response_length == 5
    assert sample.body_fingerprint is not None
    assert sample.errors == ()


def test_build_timing_sample_from_transport_failure():
    replay = make_replay_result(
        status=None,
        body=None,
        executed=False,
        errors=["connection failed"],
    )

    sample = build_timing_sample(
        request_number=1,
        response_time_ms=50.0,
        replay_result=replay,
    )

    assert sample.status is None
    assert sample.response_length is None
    assert sample.body_fingerprint is None
    assert sample.errors == ("connection failed",)


def test_execute_timed_replay_measures_wall_clock_elapsed_time(
    monkeypatch,
):
    replay = make_replay_result()

    times = iter([10.0, 10.250])

    monkeypatch.setattr(
        "backend.verification.sqli_timing.time.monotonic",
        lambda: next(times),
    )

    monkeypatch.setattr(
        "backend.verification.sqli_timing.execute_replay",
        lambda **kwargs: replay,
    )

    request = ReplayRequest(
        method="GET",
        url="http://test.local/item?id=1",
        headers={},
        body=None,
    )

    result = execute_timed_replay(
        finding_id="F-SQLI-001",
        request=request,
        request_number=1,
    )

    assert result.sample.response_time_ms == pytest.approx(
        250.0
    )


def test_collect_timing_samples_calls_execute_timed_replay_n_times(
    monkeypatch,
):
    calls = []

    def fake_execute_timed_replay(
        finding_id,
        request,
        request_number,
        timeout_seconds,
    ):
        calls.append(request_number)

        return TimedReplay(
            sample=make_sample(
                number=request_number,
                response_time_ms=100.0,
            ),
            replay_result=make_replay_result(),
        )

    monkeypatch.setattr(
        "backend.verification.sqli_timing.execute_timed_replay",
        fake_execute_timed_replay,
    )

    request = ReplayRequest(
        method="GET",
        url="http://test.local/item?id=1",
        headers={},
        body=None,
    )

    results = collect_timing_samples(
        finding_id="F-SQLI-001",
        request=request,
        count=3,
    )

    assert len(results) == 3
    assert calls == [1, 2, 3]


def test_baseline_statistics_use_median_absolute_deviation():
    statistics = compute_baseline_statistics(
        [100.0, 105.0, 110.0, 95.0, 100.0]
    )

    assert statistics.valid_sample_count == 5
    assert statistics.median_ms == 100.0
    assert statistics.mad_ms == 5.0
    assert statistics.variation_ratio == 0.05


def test_stable_baseline_passes():
    profile = get_sqli_replay_profile(
        SqliSubtype.TIME_BASED
    )

    statistics = compute_baseline_statistics(
        [100.0, 105.0, 110.0, 95.0, 100.0]
    )

    result = evaluate_baseline_stability(
        statistics,
        profile,
    )

    assert result.stable is True
    assert result.reasons == ()


def test_baseline_with_too_few_samples_is_unstable():
    profile = get_sqli_replay_profile(
        SqliSubtype.TIME_BASED
    )

    statistics = compute_baseline_statistics(
        [100.0, 105.0, 95.0, 100.0]
    )

    result = evaluate_baseline_stability(
        statistics,
        profile,
    )

    assert result.stable is False


def test_baseline_with_excessive_mad_ratio_is_unstable():
    profile = get_sqli_replay_profile(
        SqliSubtype.TIME_BASED
    )

    statistics = compute_baseline_statistics(
        [60.0, 100.0, 140.0, 100.0, 160.0]
    )

    assert statistics.median_ms == 100.0
    assert statistics.mad_ms == 40.0
    assert statistics.variation_ratio == 0.40

    result = evaluate_baseline_stability(
        statistics,
        profile,
    )

    assert result.stable is False


def test_401_trial_is_invalid():
    sample = make_sample(
        number=1,
        response_time_ms=100.0,
        status=401,
    )

    result = evaluate_trial_validity(sample)

    assert result.valid is False


def test_measured_500_trial_is_valid():
    sample = make_sample(
        number=1,
        response_time_ms=2500.0,
        status=500,
    )

    result = evaluate_trial_validity(sample)

    assert result.valid is True


def test_transport_failure_is_invalid():
    sample = make_sample(
        number=1,
        response_time_ms=20.0,
        status=None,
    )

    result = evaluate_trial_validity(sample)

    assert result.valid is False


def test_trial_delay_requires_absolute_and_ratio_thresholds():
    profile = get_sqli_replay_profile(
        SqliSubtype.TIME_BASED
    )

    result = evaluate_trial_delay(
        sample=make_sample(
            number=1,
            response_time_ms=2500.0,
        ),
        baseline_median_ms=100.0,
        baseline_mad_ms=10.0,
        profile=profile,
    )

    assert result.delay_ms == 2400.0
    assert result.ratio == 25.0
    assert result.delayed is True


def test_trial_below_absolute_delay_is_not_delayed():
    profile = get_sqli_replay_profile(
        SqliSubtype.TIME_BASED
    )

    result = evaluate_trial_delay(
        sample=make_sample(
            number=1,
            response_time_ms=1900.0,
        ),
        baseline_median_ms=100.0,
        baseline_mad_ms=10.0,
        profile=profile,
    )

    assert result.delayed is False


def test_verification_statistics():
    statistics = compute_verification_statistics(
        [2500.0, 2600.0, 2700.0],
        baseline_median_ms=100.0,
    )

    assert statistics.valid_trial_count == 3
    assert statistics.median_ms == 2600.0
    assert statistics.timing_delta_ms == 2500.0
    assert statistics.timing_ratio == 26.0


def test_verification_collection_retries_invalid_trial(
    monkeypatch,
):
    profile = get_sqli_replay_profile(
        SqliSubtype.TIME_BASED
    )

    samples = [
        make_sample(
            number=1,
            response_time_ms=50.0,
            status=401,
        ),
        make_sample(
            number=2,
            response_time_ms=2500.0,
        ),
        make_sample(
            number=3,
            response_time_ms=2600.0,
        ),
        make_sample(
            number=4,
            response_time_ms=2700.0,
        ),
    ]

    index = {"value": 0}

    def fake_execute_timed_replay(
        finding_id,
        request,
        request_number,
        timeout_seconds,
    ):
        sample = samples[index["value"]]
        index["value"] += 1

        return TimedReplay(
            sample=sample,
            replay_result=make_replay_result(
                status=sample.status,
            ),
        )

    monkeypatch.setattr(
        "backend.verification.sqli_timing.execute_timed_replay",
        fake_execute_timed_replay,
    )

    request = ReplayRequest(
        method="GET",
        url="http://test.local/item?id=1",
        headers={},
        body=None,
    )

    result = collect_verification_trials(
        finding_id="F-SQLI-001",
        request=request,
        profile=profile,
    )

    assert len(result.attempts) == 4
    assert len(result.valid_trials) == 3