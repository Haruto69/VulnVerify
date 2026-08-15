from backend.verification.csrf_confidence import (
    calculate_csrf_confidence,
)


def test_independent_state_change_has_highest_confidence():
    confidence = calculate_csrf_confidence(
        independent_state_change_verified=True,
    )

    assert confidence == 0.99


def test_protection_enforcement_has_high_confidence():
    confidence = calculate_csrf_confidence(
        protection_enforcement_verified=True,
    )

    assert confidence == 0.97


def test_deterministic_indicator_has_medium_high_confidence():
    confidence = calculate_csrf_confidence(
        deterministic_indicator_matched=True,
    )

    assert confidence == 0.85


def test_partial_evidence_has_low_confidence():
    confidence = calculate_csrf_confidence(
        partial_evidence_available=True,
    )

    assert confidence == 0.40


def test_insufficient_evidence_has_lowest_confidence():
    confidence = calculate_csrf_confidence()

    assert confidence == 0.25


def test_strongest_available_evidence_wins():
    confidence = calculate_csrf_confidence(
        independent_state_change_verified=True,
        protection_enforcement_verified=True,
        deterministic_indicator_matched=True,
        partial_evidence_available=True,
    )

    assert confidence == 0.99


def test_protection_beats_indicator():
    confidence = calculate_csrf_confidence(
        protection_enforcement_verified=True,
        deterministic_indicator_matched=True,
    )

    assert confidence == 0.97