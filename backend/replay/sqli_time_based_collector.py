from dataclasses import dataclass

from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayRequest
from backend.replay.sqli_time_based import (
    build_time_based_replay_requests,
)
from backend.verification.sqli_profiles import (
    SqliSubtype,
    get_sqli_replay_profile,
)
from backend.verification.sqli_timing import (
    TimingSample,
    TimedReplay,
    VerificationTrialCollection,
    collect_timing_samples,
    collect_verification_trials,
)


@dataclass(frozen=True)
class SqliTimeBasedReplayEvidence:
    """
    Raw replay evidence collected for one TIME_BASED SQLi
    verification run.

    Classification does not happen in this layer.
    """

    baseline_request: ReplayRequest
    verification_request: ReplayRequest

    baseline_attempts: tuple[TimedReplay, ...]

    verification_attempts: tuple[TimedReplay, ...]
    valid_verification_trials: tuple[TimedReplay, ...]

    @property
    def baseline_samples(
        self,
    ) -> tuple[TimingSample, ...]:
        return tuple(
            attempt.sample
            for attempt in self.baseline_attempts
        )

    @property
    def verification_samples(
        self,
    ) -> tuple[TimingSample, ...]:
        return tuple(
            attempt.sample
            for attempt in self.verification_attempts
        )

    @property
    def valid_verification_samples(
        self,
    ) -> tuple[TimingSample, ...]:
        return tuple(
            attempt.sample
            for attempt in self.valid_verification_trials
        )


def collect_time_based_replay_evidence(
    *,
    finding: NormalizedFinding,
    baseline_parameter_value: str,
    timeout_seconds: float = 10.0,
    session_cookie_override: str | None = None,
) -> SqliTimeBasedReplayEvidence:
    """
    Collect baseline and verification timing evidence.

    Baseline:
        uses the restored pre-injection parameter value.

    Verification:
        uses the exact scanner-captured injected request.

    This function does not generate payloads, calculate confidence,
    infer network/server explanations, or classify the finding.
    """

    profile = get_sqli_replay_profile(
        SqliSubtype.TIME_BASED
    )

    (
        baseline_request,
        verification_request,
    ) = build_time_based_replay_requests(
        finding=finding,
        baseline_parameter_value=baseline_parameter_value,
        session_cookie_override=session_cookie_override,
    )

    baseline_attempts = collect_timing_samples(
        finding_id=finding.finding_id,
        request=baseline_request,
        count=profile.baseline_attempts_preferred,
        timeout_seconds=timeout_seconds,
    )

    verification_collection: VerificationTrialCollection = (
        collect_verification_trials(
            finding_id=finding.finding_id,
            request=verification_request,
            profile=profile,
            timeout_seconds=timeout_seconds,
        )
    )

    return SqliTimeBasedReplayEvidence(
        baseline_request=baseline_request,
        verification_request=verification_request,
        baseline_attempts=tuple(
            baseline_attempts
        ),
        verification_attempts=(
            verification_collection.attempts
        ),
        valid_verification_trials=(
            verification_collection.valid_trials
        ),
    )