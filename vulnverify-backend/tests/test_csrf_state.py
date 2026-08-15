from backend.verification.csrf_state import (
    CsrfStateObservation,
    derive_state_change_observed,
    has_strong_acceptance_evidence,
)


def test_state_change_observed():
    observation = CsrfStateObservation(
        before_state_observed=True,
        after_state_observed=True,
        state_changed=True,
        observation_method="profile_state_check",
    )

    result = derive_state_change_observed(
        observation
    )

    assert result is True


def test_state_confirmed_unchanged():
    observation = CsrfStateObservation(
        before_state_observed=True,
        after_state_observed=True,
        state_changed=False,
        observation_method="profile_state_check",
    )

    result = derive_state_change_observed(
        observation
    )

    assert result is False


def test_state_unknown_when_before_state_missing():
    observation = CsrfStateObservation(
        before_state_observed=False,
        after_state_observed=True,
        state_changed=None,
    )

    result = derive_state_change_observed(
        observation
    )

    assert result is None


def test_state_unknown_when_after_state_missing():
    observation = CsrfStateObservation(
        before_state_observed=True,
        after_state_observed=False,
        state_changed=None,
    )

    result = derive_state_change_observed(
        observation
    )

    assert result is None


def test_strong_acceptance_indicator_matches():
    observation = CsrfStateObservation(
        deterministic_acceptance_indicator=(
            "Password Changed."
        ),
        deterministic_acceptance_indicator_matched=True,
        observation_method="response_indicator",
    )

    assert (
        has_strong_acceptance_evidence(
            observation
        )
        is True
    )


def test_acceptance_indicator_not_matched():
    observation = CsrfStateObservation(
        deterministic_acceptance_indicator=(
            "Password Changed."
        ),
        deterministic_acceptance_indicator_matched=False,
        observation_method="response_indicator",
    )

    assert (
        has_strong_acceptance_evidence(
            observation
        )
        is False
    )


def test_missing_acceptance_indicator_is_not_evidence():
    observation = CsrfStateObservation()

    assert (
        has_strong_acceptance_evidence(
            observation
        )
        is False
    )