from pydantic import BaseModel

from backend.replay.csrf import CsrfOriginReplayResult


class CsrfOriginObservation(BaseModel):
    rejection_attributable_to_origin_policy: bool = False
    origin_or_referer_enforced: bool = False


def evaluate_csrf_origin_policy(
    replay_result: CsrfOriginReplayResult,
    *,
    rejection_attributable_to_origin_policy: bool,
) -> CsrfOriginObservation:
    """
    Evaluate whether the application appears to enforce an
    Origin/Referer-based CSRF defense.

    A rejection response alone is not enough. The rejection must be
    attributable to the forged cross-site Origin/Referer values.
    """

    enforced = (
        replay_result.rejection_observed
        and rejection_attributable_to_origin_policy
    )

    return CsrfOriginObservation(
        rejection_attributable_to_origin_policy=(
            rejection_attributable_to_origin_policy
        ),
        origin_or_referer_enforced=enforced,
    )