from datetime import datetime, timezone

import pytest

from backend.models.replay_result import (
    ReplayExecution,
    ReplayRequest,
    ReplayResponse,
    ReplayResult,
)
from backend.verification import sqli_timing


# ---------------------------------------------------------------------
# median()
# ---------------------------------------------------------------------


def test_median_with_odd_count():
    assert sqli_timing.median(
        [5.0, 1.0, 3.0]
    ) == 3.0


def test_median_with_even_count():
    assert sqli_timing.median(
        [1.0, 2.0, 3.0, 4.0]
    ) == 2.5


def test_median_with_single_value():
    assert sqli_timing.median([42.0]) == 42.0


def test_median_with_unsorted_duplicates():
    assert sqli_timing.median(
        [10.0, 10.0, 1.0, 100.0, 10.0]
    ) == 10.0


def test_median_with_empty_list_raises():
    with pytest.raises(ValueError):
        sqli_timing.median([])


# ---------------------------------------------------------------------
# build_timing_sample()
# ---------------------------------------------------------------------


def _replay_request() -> ReplayRequest:
    return ReplayRequest(
        method="GET",
        url="http://127.0.0.1/DVWA/vulnerabilities/sqli/?id=1",
        headers={},
        body=None,
    )


def test_build_timing_sample_from_successful_replay():
    fixed_timestamp = datetime(
        2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc
    )

    replay_result = ReplayResult(
        finding_id="finding-timing-001",
        replay=ReplayExecution(
            executed=True,
            timestamp=fixed_timestamp,
            request=_replay_request(),
            response=ReplayResponse(
                status=200,
                headers={"content-type": "text/html"},
                body="hello world",
            ),
        ),
        observations=[],
        errors=[],
    )

    sample = sqli_timing.build_timing_sample(
        request_number=1,
        response_time_ms=123.4,
        replay_result=replay_result,
    )

    assert sample.request_number == 1
    assert sample.timestamp == fixed_timestamp
    assert sample.status == 200
    assert sample.response_time_ms == 123.4
    assert sample.response_length == len("hello world")
    assert sample.body_fingerprint == (
        "b94d27b9934d3e08a52e52d7da7dabfa"
        "c484efe37a5380ee9088f7ace2efcde9"
    )
    assert sample.headers == {"content-type": "text/html"}
    assert sample.errors == ()


def test_build_timing_sample_from_transport_failure():
    fixed_timestamp = datetime(
        2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc
    )

    replay_result = ReplayResult(
        finding_id="finding-timing-002",
        replay=ReplayExecution(
            executed=True,
            timestamp=fixed_timestamp,
            request=_replay_request(),
            response=ReplayResponse(
                status=None,
                headers={},
                body=None,
            ),
        ),
        observations=[],
        errors=["ConnectError: Connection refused"],
    )

    sample = sqli_timing.build_timing_sample(
        request_number=2,
        response_time_ms=5000.0,
        replay_result=replay_result,
    )

    assert sample.status is None
    assert sample.response_length is None
    assert sample.body_fingerprint is None
    assert sample.errors == (
        "ConnectError: Connection refused",
    )


# ---------------------------------------------------------------------
# execute_timed_replay() - Option A wall-clock wrapper
# ---------------------------------------------------------------------


def test_execute_timed_replay_measures_wall_clock_elapsed_time(
    monkeypatch,
):
    call_times = iter([100.0, 100.25])

    monkeypatch.setattr(
        sqli_timing.time,
        "monotonic",
        lambda: next(call_times),
    )

    fixed_timestamp = datetime(
        2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc
    )

    request = _replay_request()

    fake_replay_result = ReplayResult(
        finding_id="finding-timed-001",
        replay=ReplayExecution(
            executed=True,
            timestamp=fixed_timestamp,
            request=request,
            response=ReplayResponse(
                status=200,
                headers={},
                body="ok",
            ),
        ),
        observations=[],
        errors=[],
    )

    def fake_execute_replay(
        finding_id,
        request,
        timeout_seconds=10.0,
    ):
        return fake_replay_result

    monkeypatch.setattr(
        sqli_timing,
        "execute_replay",
        fake_execute_replay,
    )

    timed_replay = sqli_timing.execute_timed_replay(
        finding_id="finding-timed-001",
        request=request,
        request_number=1,
    )

    assert timed_replay.sample.request_number == 1
    assert timed_replay.sample.response_time_ms == pytest.approx(
        250.0
    )
    assert timed_replay.sample.status == 200
    assert timed_replay.replay_result is fake_replay_result


# ---------------------------------------------------------------------
# collect_timing_samples()
# ---------------------------------------------------------------------


def test_collect_timing_samples_calls_execute_timed_replay_n_times(
    monkeypatch,
):
    recorded_request_numbers = []

    def fake_execute_timed_replay(
        finding_id,
        request,
        request_number,
        timeout_seconds=10.0,
    ):
        recorded_request_numbers.append(request_number)

        fixed_timestamp = datetime(
            2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc
        )

        replay_result = ReplayResult(
            finding_id=finding_id,
            replay=ReplayExecution(
                executed=True,
                timestamp=fixed_timestamp,
                request=request,
                response=ReplayResponse(
                    status=200,
                    headers={},
                    body="ok",
                ),
            ),
            observations=[],
            errors=[],
        )

        sample = sqli_timing.build_timing_sample(
            request_number=request_number,
            response_time_ms=10.0,
            replay_result=replay_result,
        )

        return sqli_timing.TimedReplay(
            sample=sample,
            replay_result=replay_result,
        )

    monkeypatch.setattr(
        sqli_timing,
        "execute_timed_replay",
        fake_execute_timed_replay,
    )

    results = sqli_timing.collect_timing_samples(
        finding_id="finding-batch-001",
        request=_replay_request(),
        count=5,
    )

    assert len(results) == 5
    assert recorded_request_numbers == [1, 2, 3, 4, 5]
    assert [
        r.sample.request_number for r in results
    ] == [1, 2, 3, 4, 5]