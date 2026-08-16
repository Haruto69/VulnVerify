import pytest
from pydantic import ValidationError

from backend.models.verification_trigger import (
    VerificationTriggerRequest,
)


def test_valid_time_based_sqli_trigger():
    trigger = VerificationTriggerRequest(
        sqli={
            "time_based": {
                "baseline_parameter_value": "1",
            }
        }
    )

    assert trigger.csrf is None
    assert trigger.sqli is not None

    assert (
        trigger.sqli.time_based.baseline_parameter_value
        == "1"
    )


def test_time_based_baseline_value_may_be_blank():
    trigger = VerificationTriggerRequest(
        sqli={
            "time_based": {
                "baseline_parameter_value": "",
            }
        }
    )

    assert (
        trigger.sqli.time_based.baseline_parameter_value
        == ""
    )


def test_sqli_trigger_uses_default_timeout():
    trigger = VerificationTriggerRequest(
        sqli={
            "time_based": {
                "baseline_parameter_value": "1",
            }
        }
    )

    assert trigger.timeout_seconds == 10.0


def test_sqli_trigger_accepts_custom_timeout():
    trigger = VerificationTriggerRequest(
        sqli={
            "time_based": {
                "baseline_parameter_value": "1",
            }
        },
        timeout_seconds=15.0,
    )

    assert trigger.timeout_seconds == 15.0


def test_empty_trigger_is_rejected():
    with pytest.raises(ValidationError):
        VerificationTriggerRequest()


def test_csrf_and_sqli_cannot_be_supplied_together():
    with pytest.raises(ValidationError):
        VerificationTriggerRequest(
            csrf={
                "state_check": {
                    "deterministic_acceptance_indicator": "ok",
                }
            },
            sqli={
                "time_based": {
                    "baseline_parameter_value": "1",
                }
            },
        )