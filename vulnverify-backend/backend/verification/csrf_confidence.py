def calculate_csrf_confidence(
    *,
    independent_state_change_verified: bool = False,
    protection_enforcement_verified: bool = False,
    deterministic_indicator_matched: bool = False,
    partial_evidence_available: bool = False,
) -> float:
    """
    Deterministic CSRF confidence policy v1.

    Confidence reflects evidence strength, independently of the
    TP / FP / INCONCLUSIVE classification.

    Evidence strength:
        independent state-change verification -> 0.99
        controlled protection enforcement     -> 0.97
        deterministic success indicator       -> 0.85
        partial / ambiguous evidence           -> 0.40
        insufficient evidence                  -> 0.25
    """

    if independent_state_change_verified:
        return 0.99

    if protection_enforcement_verified:
        return 0.97

    if deterministic_indicator_matched:
        return 0.85

    if partial_evidence_available:
        return 0.40

    return 0.25