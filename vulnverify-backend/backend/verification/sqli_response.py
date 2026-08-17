import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from itertools import combinations

from backend.models.replay_result import ReplayResult


BASELINE_MIN_VALID_SAMPLES = 3
BASELINE_MAX_VALID_SAMPLES = 5
BASELINE_SIMILARITY_MIN = 0.98
BASELINE_LENGTH_DIFFERENCE_MAX = 0.02
BOOLEAN_MATERIAL_SIMILARITY_MAX = 0.80


@dataclass(frozen=True)
class ResponseObservation:
    status_code: int | None
    body: str
    valid: bool = True
    failure_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class StableBaselineResult:
    stable: bool
    selected_indices: tuple[int, ...]
    normalized_bodies: tuple[str, ...]
    reason: str | None = None


def normalize_response_body(
    body: str | None,
) -> str:
    text = body or ""

    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")

    normalized_lines = []

    for line in text.split("\n"):
        line = line.rstrip()
        line = re.sub(r"[\t\f\v ]+", " ", line)
        normalized_lines.append(line)

    return "\n".join(normalized_lines)


def response_similarity(
    first_body: str,
    second_body: str,
) -> float:
    return SequenceMatcher(
        None,
        normalize_response_body(first_body),
        normalize_response_body(second_body),
    ).ratio()


def normalized_length_difference(
    first_body: str,
    second_body: str,
) -> float:
    first = normalize_response_body(first_body)
    second = normalize_response_body(second_body)

    return abs(len(first) - len(second)) / max(
        len(first),
        len(second),
        1,
    )


def evaluate_non_time_baseline(
    samples: list[ResponseObservation],
) -> StableBaselineResult:
    valid_samples = [
        (index, sample)
        for index, sample in enumerate(samples)
        if sample.valid
    ][:BASELINE_MAX_VALID_SAMPLES]

    if len(valid_samples) < BASELINE_MIN_VALID_SAMPLES:
        return StableBaselineResult(
            stable=False,
            selected_indices=(),
            normalized_bodies=(),
            reason=(
                "Fewer than three valid baseline responses were "
                "available."
            ),
        )

    first_three = valid_samples[:3]

    if _stable_response_class(first_three):
        return _build_stable_result(first_three)

    if len(valid_samples) < BASELINE_MAX_VALID_SAMPLES:
        return StableBaselineResult(
            stable=False,
            selected_indices=(),
            normalized_bodies=(),
            reason=(
                "The first three valid baseline responses were "
                "inconsistent and fewer than five valid samples "
                "were available."
            ),
        )

    for candidate in combinations(valid_samples, 3):
        candidate_list = list(candidate)

        if _stable_response_class(candidate_list):
            return _build_stable_result(candidate_list)

    return StableBaselineResult(
        stable=False,
        selected_indices=(),
        normalized_bodies=(),
        reason=(
            "No stable response class of three exists among the "
            "first five valid baseline samples."
        ),
    )


def replay_to_response_observation(
    replay_result: ReplayResult,
) -> ResponseObservation:
    response = replay_result.replay.response
    status_code = response.status

    failure_reasons = tuple(replay_result.errors)

    invalid_status = status_code in {
        401,
        403,
        419,
        429,
    }

    valid = (
        replay_result.replay.executed
        and status_code is not None
        and not invalid_status
        and not failure_reasons
    )

    return ResponseObservation(
        status_code=status_code,
        body=response.body or "",
        valid=valid,
        failure_reasons=failure_reasons,
    )


def _stable_response_class(
    samples: list[tuple[int, ResponseObservation]],
) -> bool:
    statuses = {
        sample.status_code
        for _, sample in samples
    }

    if len(statuses) != 1:
        return False

    for (_, first), (_, second) in combinations(samples, 2):
        similarity = response_similarity(
            first.body,
            second.body,
        )

        if similarity < BASELINE_SIMILARITY_MIN:
            return False

        length_difference = normalized_length_difference(
            first.body,
            second.body,
        )

        if length_difference > BASELINE_LENGTH_DIFFERENCE_MAX:
            return False

    return True


def _build_stable_result(
    samples: list[tuple[int, ResponseObservation]],
) -> StableBaselineResult:
    return StableBaselineResult(
        stable=True,
        selected_indices=tuple(
            index
            for index, _ in samples
        ),
        normalized_bodies=tuple(
            normalize_response_body(sample.body)
            for _, sample in samples
        ),
        reason=None,
    )
