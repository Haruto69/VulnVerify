import pytest
from pydantic import ValidationError

from backend.verification.xss_context import (
    XssBlockingReason,
    XssSubtype,
    XssVerificationContext,
)


def test_valid_reflected_context():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        replay_completed_successfully=True,
        independent_replay_attempts=2,
        verification_confidence=0.90,
    )

    assert context.subtype == XssSubtype.REFLECTED
    assert context.replay_completed_successfully is True
    assert context.independent_replay_attempts == 2


def test_valid_stored_context():
    context = XssVerificationContext(
        subtype=XssSubtype.STORED,
        stored_injection_completed=True,
        stored_render_page_reached=True,
        verification_confidence=0.90,
    )

    assert context.stored_injection_completed is True
    assert context.stored_render_page_reached is True


def test_valid_dom_context():
    context = XssVerificationContext(
        subtype=XssSubtype.DOM_BASED,
        dom_attacker_controlled_data_reached_sink=True,
        verification_confidence=0.90,
    )

    assert (
        context.dom_attacker_controlled_data_reached_sink
        is True
    )


def test_unknown_subtype_is_supported_for_manual_triage():
    context = XssVerificationContext(
        subtype=XssSubtype.UNKNOWN,
        verification_confidence=0.20,
    )

    assert context.subtype == XssSubtype.UNKNOWN


def test_structured_blocking_reason():
    context = XssVerificationContext(
        subtype=XssSubtype.REFLECTED,
        blocking_reason=XssBlockingReason.AUTH_SESSION_FAILURE,
        verification_confidence=0.20,
    )

    assert (
        context.blocking_reason
        == XssBlockingReason.AUTH_SESSION_FAILURE
    )


def test_confidence_must_not_exceed_one():
    with pytest.raises(ValidationError):
        XssVerificationContext(
            subtype=XssSubtype.REFLECTED,
            verification_confidence=1.1,
        )


def test_attempt_count_cannot_be_negative():
    with pytest.raises(ValidationError):
        XssVerificationContext(
            subtype=XssSubtype.REFLECTED,
            independent_replay_attempts=-1,
            verification_confidence=0.50,
        )