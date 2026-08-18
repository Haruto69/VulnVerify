from pydantic import BaseModel

from backend.replay.csrf import CsrfTokenReplayResult


class CsrfDefenseObservation(BaseModel):
    rejection_attributable_to_csrf_defense: bool = False
    defense_enforced: bool = False


def evaluate_csrf_defense(
    replay_result: CsrfTokenReplayResult,
    *,
    rejection_attributable_to_csrf_defense: bool,
) -> CsrfDefenseObservation:
    """
    Evaluate whether a known CSRF token/custom-header defense appears
    to be enforced.

    A rejection status alone is not sufficient. The rejection must
    also be attributable to the CSRF defense that was removed.
    """

    defense_enforced = (
        replay_result.defense_removed
        and replay_result.rejection_observed
        and rejection_attributable_to_csrf_defense
    )

    return CsrfDefenseObservation(
        rejection_attributable_to_csrf_defense=(
            rejection_attributable_to_csrf_defense
        ),
        defense_enforced=defense_enforced,
    )