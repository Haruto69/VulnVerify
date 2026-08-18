"""
TIME_BASED SQLi timing observation and statistics layer.

Formulas and thresholds below are taken verbatim from
SQLi_Time_Based_Verification_Clarifications_v1.xlsx (sheets:
Time_Based_Clarifications, Time_Based_Config, Formulas,
Time_Decision_Rules). They are confirmed, not inferred:

- baseline_median = median(valid baseline response_time_ms)
- absolute_deviation_i = abs(sample_i - baseline_median)
- baseline_MAD = median(all absolute_deviation_i)
- baseline_variation_ratio = baseline_MAD / baseline_median
- A baseline is stable iff valid_sample_count >= baseline_attempts_min
  AND baseline_variation_ratio <= baseline_mad_ratio_max (0.20 by
  default).
- individual_trial_delay_ms = trial_response_time_ms - baseline_median
- individual_trial_delay_threshold = max(2000 ms, 5 x baseline_MAD)
- individual_trial_ratio = trial_response_time_ms / baseline_median
- A verification trial counts as "delayed" iff it is valid AND
  individual_trial_delay_ms >= individual_trial_delay_threshold AND
  individual_trial_ratio >= trial_ratio_min (2.0 by default).
- A valid verification trial is one that completes with a measured
  response_time_ms and has no failure-contract condition (timeout,
  connection/DNS failure, auth/session failure, WAF/rate-limit
  block). A measured 5xx is valid; it is not SQLi proof by itself.
- verification_median = median(valid verification response_time_ms)
- timing_delta_ms = verification_median - baseline_median
- timing_ratio = verification_median / baseline_median (secondary
  observation only, never a substitute for the delay/reproducibility
  rules).
- Reproducibility: at least tp_delayed_trials_required (2) of the
  first verification_min_trials (3) valid verification trials must
  independently satisfy the per-trial delay rule. If fewer than
  verification_min_trials valid trials remain after up to
  verification_max_trials (5) attempts, the result is INCONCLUSIVE.

Timing capture itself uses Option A: a SQLi-specific wrapper measures
wall-clock elapsed time around calls to the existing, frozen
backend.replay.engine.execute_replay(). ReplayResult v1 is not
modified and does not gain a response_time_ms field.

Still open, NOT implemented here or anywhere in this module:

- How to detect "no credible network/server explanation" for the
  TRUE_POSITIVE rule. This is exposed as an explicit boolean the
  caller must supply; it is never inferred from timing data.
- A confidence-score formula for TIME_BASED SQLi (CSRF has
  calculate_csrf_confidence(); SQLi does not have an equivalent yet).
  Confidence remains a required external input.
- ERROR_BASED / BOOLEAN_BASED / UNION_BASED statistics or
  classification. Out of scope for this module.
"""

import hashlib
import time
from dataclasses import dataclass
from datetime import datetime

from backend.models.replay_result import ReplayRequest, ReplayResult
from backend.replay.engine import execute_replay
from backend.verification.sqli_failure import (
    SqliFailureContext,
    SqliFailureEvaluation,
    evaluate_sqli_failure,
)
from backend.verification.sqli_profiles import SqliReplayProfile


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
    (e.g. from SqliReplayProfile.baseline_attempts_preferred). Used for
    baseline collection, which the clarifications spreadsheet does not
    define a retry/backoff policy for.
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


# ---------------------------------------------------------------------
# Baseline statistics and stability
# (Time_Based_Clarifications: "What does MAD mean?",
#  "What is a stable baseline?"; Formulas sheet)
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class BaselineStatistics:
    valid_sample_count: int
    median_ms: float
    mad_ms: float
    variation_ratio: float


def compute_baseline_statistics(
    valid_response_times: list[float],
) -> BaselineStatistics:
    """
    baseline_median = median(valid baseline response_time_ms)
    absolute_deviation_i = abs(sample_i - baseline_median)
    baseline_MAD = median(all absolute_deviation_i)
    baseline_variation_ratio = baseline_MAD / baseline_median
    """

    baseline_median = median(valid_response_times)

    absolute_deviations = [
        abs(value - baseline_median)
        for value in valid_response_times
    ]
    baseline_mad = median(absolute_deviations)

    variation_ratio = (
        baseline_mad / baseline_median
        if baseline_median
        else float("inf")
    )

    return BaselineStatistics(
        valid_sample_count=len(valid_response_times),
        median_ms=baseline_median,
        mad_ms=baseline_mad,
        variation_ratio=variation_ratio,
    )


@dataclass(frozen=True)
class BaselineStabilityResult:
    stable: bool
    reasons: tuple[str, ...]


def evaluate_baseline_stability(
    statistics: BaselineStatistics,
    profile: SqliReplayProfile,
) -> BaselineStabilityResult:
    """
    Stable baseline = valid_sample_count >= baseline_attempts_min AND
    baseline_variation_ratio <= baseline_mad_ratio_max (0.20 default).
    Both conditions are required; sample count alone is not enough.
    """

    reasons: list[str] = []

    if statistics.valid_sample_count < profile.baseline_attempts_min:
        reasons.append(
            f"Only {statistics.valid_sample_count} valid baseline "
            f"samples were obtained; at least "
            f"{profile.baseline_attempts_min} are required."
        )

    if (
        profile.baseline_mad_ratio_max is not None
        and statistics.variation_ratio
        > profile.baseline_mad_ratio_max
    ):
        reasons.append(
            f"Baseline variation ratio "
            f"{statistics.variation_ratio:.4f} exceeds the maximum "
            f"stable ratio of {profile.baseline_mad_ratio_max:.4f}."
        )

    return BaselineStabilityResult(
        stable=not reasons,
        reasons=tuple(reasons),
    )


# ---------------------------------------------------------------------
# Valid trial evaluation
# (Time_Based_Clarifications: "What is a valid verification trial?")
# ---------------------------------------------------------------------


def build_sqli_failure_context_from_timing_sample(
    sample: TimingSample,
) -> SqliFailureContext:
    """
    Build a SqliFailureContext from a raw TimingSample using only
    facts that are mechanically knowable from replay transport/status
    data: the HTTP status code, and whether the transport failed
    entirely (ReplayResult v1's frozen contract: status=None means the
    request never completed).

    Authentication/session/WAF/login-redirect detection requires
    application-specific context (e.g. known login-page markers) that
    is not available from timing data alone. Those flags remain False
    here; an orchestration layer with that context must supply them
    separately when it exists. A measured 5xx is deliberately NOT
    treated as invalidating here, per the clarifications spreadsheet.
    """

    return SqliFailureContext(
        status_code=sample.status,
        connection_failure=sample.status is None,
    )


@dataclass(frozen=True)
class TrialValidity:
    valid: bool
    failure_evaluation: SqliFailureEvaluation


def evaluate_trial_validity(
    sample: TimingSample,
) -> TrialValidity:
    """
    A trial is valid iff it does not trigger any condition in the
    existing, shared sqli_failure.py failure contract.
    """

    failure_evaluation = evaluate_sqli_failure(
        build_sqli_failure_context_from_timing_sample(sample)
    )

    return TrialValidity(
        valid=not failure_evaluation.inconclusive,
        failure_evaluation=failure_evaluation,
    )


# ---------------------------------------------------------------------
# Individual trial delay rule
# (Time_Based_Clarifications: "What must one verification trial
#  satisfy to count as delayed?")
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class TrialDelayResult:
    delay_ms: float
    ratio: float
    delayed: bool


def evaluate_trial_delay(
    sample: TimingSample,
    baseline_median_ms: float,
    baseline_mad_ms: float,
    profile: SqliReplayProfile,
) -> TrialDelayResult:
    """
    individual_trial_delay_ms = trial_response_time_ms - baseline_median
    individual_trial_delay_threshold = max(2000 ms, 5 x baseline_MAD)
    individual_trial_ratio = trial_response_time_ms / baseline_median

    A trial is delayed iff delay_ms >= threshold AND ratio >=
    trial_ratio_min (2.0 default). Validity is evaluated separately
    by evaluate_trial_validity() and is not re-checked here.
    """

    if (
        profile.timing_delta_floor_ms is None
        or profile.timing_mad_multiplier is None
        or profile.trial_ratio_min is None
    ):
        raise ValueError(
            "profile is missing TIME_BASED thresholds required for "
            "trial delay evaluation"
        )

    delay_ms = sample.response_time_ms - baseline_median_ms

    threshold = max(
        profile.timing_delta_floor_ms,
        profile.timing_mad_multiplier * baseline_mad_ms,
    )

    ratio = (
        sample.response_time_ms / baseline_median_ms
        if baseline_median_ms
        else float("inf")
    )

    delayed = (
        delay_ms >= threshold
        and ratio >= profile.trial_ratio_min
    )

    return TrialDelayResult(
        delay_ms=delay_ms,
        ratio=ratio,
        delayed=delayed,
    )


# ---------------------------------------------------------------------
# Aggregate verification statistics
# (Formulas sheet: verification_median, timing_delta_ms, timing_ratio)
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationStatistics:
    valid_trial_count: int
    median_ms: float
    timing_delta_ms: float
    timing_ratio: float


def compute_verification_statistics(
    valid_response_times: list[float],
    baseline_median_ms: float,
) -> VerificationStatistics:
    """
    verification_median = median(valid verification response_time_ms)
    timing_delta_ms = verification_median - baseline_median
    timing_ratio = verification_median / baseline_median (secondary
    observation only, per the clarifications spreadsheet).
    """

    verification_median = median(valid_response_times)

    timing_ratio = (
        verification_median / baseline_median_ms
        if baseline_median_ms
        else float("inf")
    )

    return VerificationStatistics(
        valid_trial_count=len(valid_response_times),
        median_ms=verification_median,
        timing_delta_ms=verification_median - baseline_median_ms,
        timing_ratio=timing_ratio,
    )


# ---------------------------------------------------------------------
# Retry-aware verification trial collection
# (Time_Based_Config: verification_min_trials=3,
#  verification_max_trials=5; Time_Based_Clarifications: "How does
#  2-of-3 work?")
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationTrialCollection:
    attempts: tuple[TimedReplay, ...]
    valid_trials: tuple[TimedReplay, ...]


def collect_verification_trials(
    finding_id: str,
    request: ReplayRequest,
    profile: SqliReplayProfile,
    timeout_seconds: float = 10.0,
) -> VerificationTrialCollection:
    """
    Execute verification replays one at a time, stopping as soon as
    profile.verification_attempts_min (3) valid trials have been
    collected, and never exceeding profile.max_attempts_per_condition
    (5) total attempts. Invalid trials (per evaluate_trial_validity)
    do not count toward the required valid total but are still
    recorded as evidence of the retry.
    """

    attempts: list[TimedReplay] = []
    valid_trials: list[TimedReplay] = []

    for attempt_number in range(
        1, profile.max_attempts_per_condition + 1
    ):
        timed_replay = execute_timed_replay(
            finding_id=finding_id,
            request=request,
            request_number=attempt_number,
            timeout_seconds=timeout_seconds,
        )
        attempts.append(timed_replay)

        if evaluate_trial_validity(timed_replay.sample).valid:
            valid_trials.append(timed_replay)

        if len(valid_trials) >= profile.verification_attempts_min:
            break

    return VerificationTrialCollection(
        attempts=tuple(attempts),
        valid_trials=tuple(valid_trials),
    )