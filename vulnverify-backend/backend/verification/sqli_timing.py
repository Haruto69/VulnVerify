"""
TIME_BASED SQLi timing observation layer.

This module ONLY covers ground that is fully unambiguous per
SQLi_Replay_Profiles_v1(1).xlsx and the confirmed working rules:

- Raw per-request timing/evidence capture (TimingSample).
- Option A timing capture: a SQLi-specific wrapper measures wall-clock
  elapsed time around calls to the existing, frozen
  backend.replay.engine.execute_replay(). ReplayResult v1 is NOT
  modified and does not gain a response_time_ms field.
- A mechanical helper to collect N timed replays in sequence.
- Standard median calculation.

Deliberately NOT implemented here, pending Cybersecurity confirmation:

- baseline_MAD (exact formula: is it
  median(abs(sample - baseline_median))?)
- timing_delta (exact definition/formula)
- timing_ratio (exact definition/formula)
- the per-trial rule for what counts as "the expected delay" for the
  ">=2 of 3 valid verification trials" requirement
- the definition of "baseline timing is stable"
- the definition of "valid timing trial" beyond the shared
  sqli_failure.py failure contract

Do not add those computations to this file until those questions are
answered. This file must not be used to derive a TRUE_POSITIVE /
FALSE_POSITIVE / INCONCLUSIVE classification on its own.
"""

import hashlib
import time
from dataclasses import dataclass
from datetime import datetime

from backend.models.replay_result import ReplayRequest, ReplayResult
from backend.replay.engine import execute_replay


@dataclass(frozen=True)
class TimingSample:
    """
    Raw, per-request timing/evidence capture for a single baseline or
    verification replay. Contains no derived/aggregate statistics.
    """

    request_number: int
    timestamp: datetime

    status: int | None
    response_time_ms: float

    response_length: int | None
    body_fingerprint: str | None

    headers: dict[str, str]
    errors: tuple[str, ...]


@dataclass(frozen=True)
class TimedReplay:
    """
    Pairs a TimingSample with the full ReplayResult it was derived
    from, so downstream code can still access the raw request/response
    for evidence purposes.
    """

    sample: TimingSample
    replay_result: ReplayResult


def build_timing_sample(
    request_number: int,
    response_time_ms: float,
    replay_result: ReplayResult,
) -> TimingSample:
    """
    Extract raw timing/evidence fields from a ReplayResult. Performs no
    interpretation of validity, stability, or classification.
    """

    response = replay_result.replay.response
    body = response.body

    if body is not None:
        response_length = len(body)
        body_fingerprint = hashlib.sha256(
            body.encode("utf-8")
        ).hexdigest()
    else:
        response_length = None
        body_fingerprint = None

    return TimingSample(
        request_number=request_number,
        timestamp=replay_result.replay.timestamp,
        status=response.status,
        response_time_ms=response_time_ms,
        response_length=response_length,
        body_fingerprint=body_fingerprint,
        headers=dict(response.headers),
        errors=tuple(replay_result.errors),
    )


def execute_timed_replay(
    finding_id: str,
    request: ReplayRequest,
    request_number: int,
    timeout_seconds: float = 10.0,
) -> TimedReplay:
    """
    Execute a single replay via the existing, frozen execute_replay()
    and measure wall-clock elapsed time around the call (Option A).
    Does not modify ReplayResult / ReplayResponse in any way.
    """

    start = time.monotonic()

    replay_result = execute_replay(
        finding_id=finding_id,
        request=request,
        timeout_seconds=timeout_seconds,
    )

    response_time_ms = (
        (time.monotonic() - start) * 1000.0
    )

    sample = build_timing_sample(
        request_number=request_number,
        response_time_ms=response_time_ms,
        replay_result=replay_result,
    )

    return TimedReplay(
        sample=sample,
        replay_result=replay_result,
    )


def collect_timing_samples(
    finding_id: str,
    request: ReplayRequest,
    count: int,
    timeout_seconds: float = 10.0,
) -> list[TimedReplay]:
    """
    Mechanically execute `count` timed replays in sequence, numbered
    starting at 1. Performs no interpretation of how many samples are
    "enough" or "stable" - that count is supplied by the caller
    (e.g. from SqliReplayProfile.baseline_attempts_preferred).
    """

    return [
        execute_timed_replay(
            finding_id=finding_id,
            request=request,
            request_number=i + 1,
            timeout_seconds=timeout_seconds,
        )
        for i in range(count)
    ]


def median(values: list[float]) -> float:
    """
    Standard median: the middle value of a sorted list, or the average
    of the two middle values when the count is even.
    """

    if not values:
        raise ValueError(
            "median() requires at least one value"
        )

    ordered = sorted(values)
    count = len(ordered)
    midpoint = count // 2

    if count % 2 == 1:
        return ordered[midpoint]

    return (
        ordered[midpoint - 1] + ordered[midpoint]
    ) / 2.0