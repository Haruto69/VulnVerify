from backend.verification.sqli_response import (
    BASELINE_LENGTH_DIFFERENCE_MAX,
    BASELINE_MAX_VALID_SAMPLES,
    BASELINE_MIN_VALID_SAMPLES,
    BASELINE_SIMILARITY_MIN,
    ResponseObservation,
    evaluate_non_time_baseline,
    normalize_response_body,
    normalized_length_difference,
    replay_to_response_observation,
    response_similarity,
)
from tests.sqli_helpers import (
    DIFFERENT_BODY,
    STABLE_BODY,
    make_replay_result,
    observation,
)


# ---------------------------------------------------------------------
# Frozen thresholds
# ---------------------------------------------------------------------


def test_non_time_baseline_thresholds():
    assert BASELINE_MIN_VALID_SAMPLES == 3
    assert BASELINE_MAX_VALID_SAMPLES == 5
    assert BASELINE_SIMILARITY_MIN == 0.98
    assert BASELINE_LENGTH_DIFFERENCE_MAX == 0.02


# ---------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------


def test_crlf_is_normalized_to_lf():
    assert normalize_response_body("a\r\nb\r\nc") == "a\nb\nc"


def test_bare_cr_is_normalized_to_lf():
    assert normalize_response_body("a\rb\rc") == "a\nb\nc"


def test_mixed_line_endings_are_normalized():
    assert (
        normalize_response_body("a\r\nb\rc\nd")
        == "a\nb\nc\nd"
    )


def test_trailing_whitespace_is_trimmed_per_line():
    assert (
        normalize_response_body("a   \nb\t\t \nc")
        == "a\nb\nc"
    )


def test_horizontal_whitespace_is_collapsed():
    assert normalize_response_body("a \t  b") == "a b"


def test_tabs_and_spaces_collapse_to_a_single_space():
    assert (
        normalize_response_body("col1\t\tcol2    col3")
        == "col1 col2 col3"
    )


def test_blank_lines_are_preserved_as_structure():
    assert normalize_response_body("a\n\nb") == "a\n\nb"


def test_leading_indentation_is_collapsed_not_removed():
    assert normalize_response_body("    <div>") == " <div>"


def test_none_body_normalizes_to_empty_string():
    assert normalize_response_body(None) == ""


def test_empty_body_normalizes_to_empty_string():
    assert normalize_response_body("") == ""


def test_numeric_ids_are_preserved():
    body = "Order 8891 belongs to account 4412"

    assert normalize_response_body(body) == body


def test_timestamps_are_preserved():
    body = "Generated at 2026-08-17T10:00:00Z"

    assert normalize_response_body(body) == body


def test_tokens_and_banners_are_preserved():
    body = (
        "csrf_token=9f8a7b6c\n"
        "Server: nginx/1.25.3\n"
        "session=abcdef123456"
    )

    assert normalize_response_body(body) == body


def test_normalization_is_idempotent():
    body = "a   \t b  \r\n  c \r\n"

    once = normalize_response_body(body)

    assert normalize_response_body(once) == once


# ---------------------------------------------------------------------
# Similarity and length difference
# ---------------------------------------------------------------------


def test_identical_bodies_have_similarity_one():
    assert response_similarity(STABLE_BODY, STABLE_BODY) == 1.0


def test_bodies_differing_only_by_line_endings_are_identical():
    assert (
        response_similarity(
            "row one\r\nrow two",
            "row one\nrow two",
        )
        == 1.0
    )


def test_bodies_differing_only_by_trailing_space_are_identical():
    assert (
        response_similarity(
            "row one   \nrow two",
            "row one\nrow two",
        )
        == 1.0
    )


def test_single_token_change_stays_above_similarity_floor():
    variant = STABLE_BODY.replace("Catalog", "Catalo9")

    assert (
        response_similarity(STABLE_BODY, variant)
        >= BASELINE_SIMILARITY_MIN
    )


def test_materially_different_bodies_fall_below_similarity_floor():
    assert (
        response_similarity(STABLE_BODY, DIFFERENT_BODY)
        < BASELINE_SIMILARITY_MIN
    )


def test_identical_bodies_have_zero_length_difference():
    assert (
        normalized_length_difference(STABLE_BODY, STABLE_BODY)
        == 0.0
    )


def test_small_append_stays_within_two_percent_length_difference():
    variant = STABLE_BODY + "XX"

    assert (
        normalized_length_difference(STABLE_BODY, variant)
        <= BASELINE_LENGTH_DIFFERENCE_MAX
    )


def test_large_append_exceeds_two_percent_length_difference():
    variant = STABLE_BODY + "X" * 30

    assert (
        normalized_length_difference(STABLE_BODY, variant)
        > BASELINE_LENGTH_DIFFERENCE_MAX
    )


def test_length_difference_uses_the_longer_body_as_denominator():
    assert normalized_length_difference("abcd", "ab") == 0.5


def test_length_difference_of_two_empty_bodies_is_zero():
    assert normalized_length_difference("", "") == 0.0


# ---------------------------------------------------------------------
# Baseline: stable first three
# ---------------------------------------------------------------------


def test_three_identical_samples_are_a_stable_baseline():
    result = evaluate_non_time_baseline(
        [observation() for _ in range(3)]
    )

    assert result.stable is True
    assert result.selected_indices == (0, 1, 2)
    assert result.reason is None
    assert len(result.normalized_bodies) == 3


def test_stable_baseline_exposes_normalized_bodies():
    result = evaluate_non_time_baseline(
        [
            observation(STABLE_BODY + "   "),
            observation(STABLE_BODY),
            observation(STABLE_BODY),
        ]
    )

    assert result.stable is True
    assert set(result.normalized_bodies) == {
        normalize_response_body(STABLE_BODY)
    }


def test_first_three_stable_samples_are_enough():
    samples = [observation() for _ in range(3)]
    samples.extend(
        observation(DIFFERENT_BODY) for _ in range(2)
    )

    result = evaluate_non_time_baseline(samples)

    assert result.stable is True
    assert result.selected_indices == (0, 1, 2)


def test_differing_status_codes_break_the_first_three():
    result = evaluate_non_time_baseline(
        [
            observation(status=200),
            observation(status=200),
            observation(status=500),
        ]
    )

    assert result.stable is False
    assert result.selected_indices == ()


def test_identical_status_codes_are_required_but_need_not_be_200():
    result = evaluate_non_time_baseline(
        [observation(status=500) for _ in range(3)]
    )

    assert result.stable is True


def test_similarity_below_floor_breaks_the_first_three():
    result = evaluate_non_time_baseline(
        [
            observation(),
            observation(),
            observation(DIFFERENT_BODY),
        ]
    )

    assert result.stable is False


def test_length_difference_above_two_percent_breaks_the_first_three():
    variant = STABLE_BODY + "X" * 12

    assert (
        response_similarity(STABLE_BODY, variant)
        >= BASELINE_SIMILARITY_MIN
    )
    assert (
        normalized_length_difference(STABLE_BODY, variant)
        > BASELINE_LENGTH_DIFFERENCE_MAX
    )

    result = evaluate_non_time_baseline(
        [
            observation(),
            observation(),
            observation(variant),
        ]
    )

    assert result.stable is False


# ---------------------------------------------------------------------
# Baseline: too few / recovery / no stable class
# ---------------------------------------------------------------------


def test_two_valid_samples_are_not_enough():
    result = evaluate_non_time_baseline(
        [observation() for _ in range(2)]
    )

    assert result.stable is False
    assert "Fewer than three" in result.reason


def test_unstable_first_three_with_only_four_samples_is_unstable():
    result = evaluate_non_time_baseline(
        [
            observation(),
            observation(),
            observation(DIFFERENT_BODY),
            observation(),
        ]
    )

    assert result.stable is False
    assert "fewer than five" in result.reason


def test_fourth_and_fifth_samples_can_recover_a_stable_class():
    samples = [
        observation(),
        observation(),
        observation(DIFFERENT_BODY),
        observation(),
        observation(),
    ]

    result = evaluate_non_time_baseline(samples)

    assert result.stable is True
    assert len(result.selected_indices) == 3
    assert 2 not in result.selected_indices


def test_no_stable_class_after_five_samples_is_unstable():
    samples = [
        observation(STABLE_BODY),
        observation(DIFFERENT_BODY),
        observation("<html><body>third variant</body></html>"),
        observation("<html><body>fourth variant here</body></html>"),
        observation("<html><body>a fifth totally other</body></html>"),
    ]

    result = evaluate_non_time_baseline(samples)

    assert result.stable is False
    assert "No stable response class" in result.reason


def test_only_the_first_five_valid_samples_are_considered():
    samples = [
        observation(DIFFERENT_BODY),
        observation("<html><body>b</body></html>"),
        observation("<html><body>ccc</body></html>"),
        observation("<html><body>dddd</body></html>"),
        observation("<html><body>eeeee</body></html>"),
        observation(),
        observation(),
        observation(),
    ]

    result = evaluate_non_time_baseline(samples)

    assert result.stable is False


# ---------------------------------------------------------------------
# Baseline: failure-contract samples are excluded
# ---------------------------------------------------------------------


def test_invalid_samples_are_excluded_from_the_baseline():
    samples = [
        observation(valid=False, failure_reasons=("WAF_BLOCKED",)),
        observation(),
        observation(),
        observation(),
    ]

    result = evaluate_non_time_baseline(samples)

    assert result.stable is True
    assert result.selected_indices == (1, 2, 3)


def test_only_invalid_samples_cannot_form_a_baseline():
    samples = [
        observation(
            valid=False,
            status=401,
            failure_reasons=("AUTHENTICATION_REQUIRED",),
        )
        for _ in range(5)
    ]

    result = evaluate_non_time_baseline(samples)

    assert result.stable is False
    assert "Fewer than three" in result.reason


def test_selected_indices_point_at_the_original_sample_positions():
    samples = [
        observation(valid=False),
        observation(),
        observation(valid=False),
        observation(),
        observation(),
    ]

    result = evaluate_non_time_baseline(samples)

    assert result.stable is True
    assert result.selected_indices == (1, 3, 4)


# ---------------------------------------------------------------------
# replay_to_response_observation()
# ---------------------------------------------------------------------


def test_successful_replay_becomes_a_valid_observation():
    result = replay_to_response_observation(
        make_replay_result()
    )

    assert isinstance(result, ResponseObservation)
    assert result.valid is True
    assert result.status_code == 200
    assert result.body == STABLE_BODY
    assert result.failure_reasons == ()


def test_401_replay_is_invalid():
    result = replay_to_response_observation(
        make_replay_result(status=401)
    )

    assert result.valid is False


def test_403_replay_is_invalid():
    result = replay_to_response_observation(
        make_replay_result(status=403)
    )

    assert result.valid is False


def test_419_replay_is_invalid():
    result = replay_to_response_observation(
        make_replay_result(status=419)
    )

    assert result.valid is False


def test_429_replay_is_invalid():
    result = replay_to_response_observation(
        make_replay_result(status=429)
    )

    assert result.valid is False


def test_measured_500_replay_stays_valid():
    result = replay_to_response_observation(
        make_replay_result(status=500)
    )

    assert result.valid is True


def test_transport_failure_replay_is_invalid():
    result = replay_to_response_observation(
        make_replay_result(
            status=None,
            body=None,
            executed=False,
            errors=["connection failure"],
        )
    )

    assert result.valid is False
    assert result.status_code is None
    assert result.body == ""
    assert result.failure_reasons == ("connection failure",)


def test_replay_errors_make_an_observation_invalid():
    result = replay_to_response_observation(
        make_replay_result(errors=["dns failure"])
    )

    assert result.valid is False
    assert result.failure_reasons == ("dns failure",)
