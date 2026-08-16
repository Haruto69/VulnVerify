from backend.models.normalized_finding import (
    NormalizedFinding,
    VulnerabilityCategory,
)
from backend.models.verified_finding import VerifiedFinding
from backend.verification.sqli_time_based import (
    verify_time_based_sqli,
)
from backend.verification.sqli_time_based_context import (
    build_sqli_time_based_context,
)
from backend.verification.sqli_timing import TimingSample


def finalize_time_based_sqli_verification(
    *,
    finding: NormalizedFinding,
    baseline_samples: list[TimingSample],
    verification_samples: list[TimingSample],
    verification_confidence: float,
    credible_network_or_server_explanation: bool = False,
) -> VerifiedFinding:
    """
    Finalize TIME_BASED SQLi verification from already-collected
    timing evidence.

    This service does not generate payloads, mutate requests,
    collect timing samples, infer confidence, or infer network/server
    explanations.
    """

    if (
        finding.vulnerability.category
        != VulnerabilityCategory.SQLI
    ):
        raise ValueError(
            "TIME_BASED SQLi verification received a non-SQLI finding"
        )

    context = build_sqli_time_based_context(
        baseline_samples=baseline_samples,
        verification_samples=verification_samples,
        verification_confidence=verification_confidence,
        credible_network_or_server_explanation=(
            credible_network_or_server_explanation
        ),
    )

    return verify_time_based_sqli(
        finding=finding,
        context=context,
    )