from dataclasses import dataclass
from enum import Enum


class SqliSubtype(str, Enum):
    ERROR_BASED = "ERROR_BASED"
    BOOLEAN_BASED = "BOOLEAN_BASED"
    TIME_BASED = "TIME_BASED"
    UNION_BASED = "UNION_BASED"


@dataclass(frozen=True)
class SqliReplayProfile:
    subtype: SqliSubtype

    baseline_attempts_min: int
    baseline_attempts_preferred: int

    verification_attempts_min: int
    max_attempts_per_condition: int

    reproduction_required_successes: int
    reproduction_trial_count: int

    timing_based: bool = False

    timing_delta_floor_ms: float | None = None
    timing_mad_multiplier: float | None = None
    verification_median_ratio: float | None = None


SQLI_REPLAY_PROFILES: dict[SqliSubtype, SqliReplayProfile] = {
    SqliSubtype.ERROR_BASED: SqliReplayProfile(
        subtype=SqliSubtype.ERROR_BASED,
        baseline_attempts_min=3,
        baseline_attempts_preferred=3,
        verification_attempts_min=3,
        max_attempts_per_condition=5,
        reproduction_required_successes=2,
        reproduction_trial_count=3,
    ),
    SqliSubtype.BOOLEAN_BASED: SqliReplayProfile(
        subtype=SqliSubtype.BOOLEAN_BASED,
        baseline_attempts_min=3,
        baseline_attempts_preferred=3,
        verification_attempts_min=3,
        max_attempts_per_condition=5,
        reproduction_required_successes=2,
        reproduction_trial_count=3,
    ),
    SqliSubtype.TIME_BASED: SqliReplayProfile(
        subtype=SqliSubtype.TIME_BASED,
        baseline_attempts_min=5,
        baseline_attempts_preferred=7,
        verification_attempts_min=3,
        max_attempts_per_condition=5,
        reproduction_required_successes=2,
        reproduction_trial_count=3,
        timing_based=True,
        timing_delta_floor_ms=2000.0,
        timing_mad_multiplier=5.0,
        verification_median_ratio=2.0,
    ),
    SqliSubtype.UNION_BASED: SqliReplayProfile(
        subtype=SqliSubtype.UNION_BASED,
        baseline_attempts_min=3,
        baseline_attempts_preferred=3,
        verification_attempts_min=3,
        max_attempts_per_condition=5,
        reproduction_required_successes=2,
        reproduction_trial_count=3,
    ),
}


def get_sqli_replay_profile(
    subtype: SqliSubtype | str,
) -> SqliReplayProfile:
    normalized_subtype = SqliSubtype(subtype)

    return SQLI_REPLAY_PROFILES[normalized_subtype]