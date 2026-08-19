from dataclasses import dataclass

from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayRequest, ReplayResult
from backend.replay.engine import execute_replay
from backend.replay.sqli_error_based import (
    build_error_based_replay_requests,
)
from backend.verification.sqli_profiles import (
    SqliSubtype,
    get_sqli_replay_profile,
)
from backend.verification.sqli_response import (
    ResponseObservation,
    replay_to_response_observation,
)


@dataclass(frozen=True)
class SqliErrorBasedReplayEvidence:
    """
    Raw replay evidence collected for one ERROR_BASED SQLi
    verification run.

    Classification does not happen in this layer -- baseline_responses
    and verification_responses are handed, unmodified, to the
    existing evaluate_error_based_sqli() classifier.
    """

    baseline_request: ReplayRequest
    verification_request: ReplayRequest

    baseline_replays: tuple[ReplayResult, ...]
    verification_replays: tuple[ReplayResult, ...]

    @property
    def baseline_responses(
        self,
    ) -> tuple[ResponseObservation, ...]:
        return tuple(
            replay_to_response_observation(replay)
            for replay in self.baseline_replays
        )

    @property
    def verification_responses(
        self,
    ) -> tuple[ResponseObservation, ...]:
        return tuple(
            replay_to_response_observation(replay)
            for replay in self.verification_replays
        )


def collect_error_based_replay_evidence(
    *,
    finding: NormalizedFinding,
    timeout_seconds: float = 10.0,
) -> SqliErrorBasedReplayEvidence:
    """
    Collect baseline and verification response evidence for
    ERROR_BASED SQLi.

    Baseline:
        the scanner-captured request with its injected payload
        removed from the tested parameter (see
        backend.replay.sqli_error_based), replayed
        profile.baseline_attempts_preferred times.

    Verification:
        the exact scanner-captured request, replayed up to
        profile.max_attempts_per_condition times, stopping once
        profile.verification_attempts_min valid trials have been
        collected. Mirrors the retry-aware pattern already used by
        backend.replay.sqli_time_based_collector.collect_verification_trials,
        generalized from timing validity to response validity via the
        existing, shared replay_to_response_observation() /
        ResponseObservation.valid contract.

    Network/replay failures are not handled specially here: a failed
    execute_replay() call already produces a ReplayResult with
    status=None and a populated errors list (see
    backend.replay.engine.execute_replay), and
    replay_to_response_observation() already marks such a result
    invalid. This function does not generate payloads, calculate
    confidence, or classify the finding.
    """

    profile = get_sqli_replay_profile(
        SqliSubtype.ERROR_BASED
    )

    (
        baseline_request,
        verification_request,
    ) = build_error_based_replay_requests(
        finding=finding,
    )

    baseline_replays = tuple(
        execute_replay(
            finding_id=finding.finding_id,
            request=baseline_request,
            timeout_seconds=timeout_seconds,
        )
        for _ in range(
            profile.baseline_attempts_preferred
        )
    )

    verification_replays: list[ReplayResult] = []
    valid_count = 0

    for _ in range(
        profile.max_attempts_per_condition
    ):
        replay_result = execute_replay(
            finding_id=finding.finding_id,
            request=verification_request,
            timeout_seconds=timeout_seconds,
        )
        verification_replays.append(replay_result)

        if replay_to_response_observation(
            replay_result
        ).valid:
            valid_count += 1

        if valid_count >= profile.verification_attempts_min:
            break

    return SqliErrorBasedReplayEvidence(
        baseline_request=baseline_request,
        verification_request=verification_request,
        baseline_replays=baseline_replays,
        verification_replays=tuple(
            verification_replays
        ),
    )
