import pytest
from pydantic import ValidationError

from backend.models.verification_trigger import (
    VerificationTriggerRequest,
)


def test_valid_csrf_defense_trigger():
    request = VerificationTriggerRequest(
        csrf={
            "defense_test": {
                "name": "csrf_token",
                "location": "QUERY",
            },
        },
    )

    assert (
        request.csrf.defense_test.name
        == "csrf_token"
    )

    assert (
        request.csrf.defense_test.location
        == "QUERY"
    )

    assert request.timeout_seconds == 10.0


def test_valid_origin_trigger():
    request = VerificationTriggerRequest(
        csrf={
            "origin_test": {
                "mutation": "BOTH",
            },
        },
    )

    assert (
        request.csrf.origin_test.mutation
        == "BOTH"
    )


def test_valid_response_indicator_trigger():
    request = VerificationTriggerRequest(
        csrf={
            "state_check": {
                "deterministic_acceptance_indicator": (
                    "Password Changed."
                ),
            },
        },
    )

    assert (
        request.csrf
        .state_check
        .deterministic_acceptance_indicator
        == "Password Changed."
    )


def test_valid_combined_trigger():
    request = VerificationTriggerRequest(
        csrf={
            "defense_test": {
                "name": "csrf_token",
                "location": "BODY",
            },
            "origin_test": {
                "mutation": "BOTH",
            },
            "state_check": {
                "deterministic_acceptance_indicator": (
                    "Profile updated"
                ),
            },
            "browser_context_required": True,
        },
        timeout_seconds=15.0,
    )

    assert (
        request.csrf.defense_test
        is not None
    )

    assert (
        request.csrf.origin_test
        is not None
    )

    assert (
        request.csrf.state_check
        is not None
    )

    assert (
        request.csrf.browser_context_required
        is True
    )

    assert request.timeout_seconds == 15.0


def test_empty_csrf_trigger_is_rejected():
    with pytest.raises(ValidationError):
        VerificationTriggerRequest(
            csrf={}
        )


def test_invalid_defense_location_is_rejected():
    with pytest.raises(ValidationError):
        VerificationTriggerRequest(
            csrf={
                "defense_test": {
                    "name": "csrf_token",
                    "location": "MAGIC",
                },
            },
        )


def test_invalid_origin_mutation_is_rejected():
    with pytest.raises(ValidationError):
        VerificationTriggerRequest(
            csrf={
                "origin_test": {
                    "mutation": "RANDOM",
                },
            },
        )


def test_empty_defense_name_is_rejected():
    with pytest.raises(ValidationError):
        VerificationTriggerRequest(
            csrf={
                "defense_test": {
                    "name": "",
                    "location": "HEADER",
                },
            },
        )


def test_timeout_must_be_positive():
    with pytest.raises(ValidationError):
        VerificationTriggerRequest(
            csrf={
                "origin_test": {
                    "mutation": "BOTH",
                },
            },
            timeout_seconds=0,
        )


def test_timeout_has_upper_bound():
    with pytest.raises(ValidationError):
        VerificationTriggerRequest(
            csrf={
                "origin_test": {
                    "mutation": "BOTH",
                },
            },
            timeout_seconds=120,
        )