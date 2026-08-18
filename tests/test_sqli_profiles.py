import pytest

from backend.verification.sqli_profiles import (
    SQLI_REPLAY_PROFILES,
    SqliSubtype,
    get_sqli_replay_profile,
)


def test_error_based_profile():
    profile = get_sqli_replay_profile(
        SqliSubtype.ERROR_BASED
    )

    assert profile.baseline_attempts_min == 3
    assert profile.verification_attempts_min == 3
    assert profile.max_attempts_per_condition == 5
    assert profile.reproduction_required_successes == 2
    assert profile.reproduction_trial_count == 3
    assert profile.timing_based is False


def test_boolean_based_profile():
    profile = get_sqli_replay_profile(
        SqliSubtype.BOOLEAN_BASED
    )

    assert profile.baseline_attempts_min == 3
    assert profile.verification_attempts_min == 3
    assert profile.reproduction_required_successes == 2


def test_time_based_profile():
    profile = get_sqli_replay_profile(
        SqliSubtype.TIME_BASED
    )

    assert profile.baseline_attempts_min == 5
    assert profile.baseline_attempts_preferred == 7

    assert profile.verification_attempts_min == 3
    assert profile.max_attempts_per_condition == 5

    assert profile.reproduction_required_successes == 2
    assert profile.reproduction_trial_count == 3

    assert profile.timing_based is True

    assert profile.timing_delta_floor_ms == 2000.0
    assert profile.timing_mad_multiplier == 5.0
    assert profile.verification_median_ratio == 2.0

    assert profile.baseline_mad_ratio_max == 0.2
    assert profile.trial_ratio_min == 2.0


def test_union_based_profile():
    profile = get_sqli_replay_profile(
        SqliSubtype.UNION_BASED
    )

    assert profile.baseline_attempts_min == 3
    assert profile.verification_attempts_min == 3
    assert profile.reproduction_required_successes == 2


def test_profile_lookup_accepts_string():
    profile = get_sqli_replay_profile(
        "TIME_BASED"
    )

    assert profile.subtype == SqliSubtype.TIME_BASED


def test_invalid_subtype_raises():
    with pytest.raises(ValueError):
        get_sqli_replay_profile(
            "NOT_A_REAL_SUBTYPE"
        )


def test_all_four_profiles_exist():
    assert set(SQLI_REPLAY_PROFILES) == {
        SqliSubtype.ERROR_BASED,
        SqliSubtype.BOOLEAN_BASED,
        SqliSubtype.TIME_BASED,
        SqliSubtype.UNION_BASED,
    }