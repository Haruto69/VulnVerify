from dataclasses import asdict, is_dataclass
from enum import Enum

from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayResult
from backend.models.verified_finding import VerifiedFinding
from backend.storage.sqli_evidence_repository import (
    save_sqli_verification_evidence,
)
from backend.verification.sqli_boolean_based import (
    BooleanComparisonTrial,
    evaluate_boolean_based_sqli,
)
from backend.verification.sqli_contract import (
    build_verified_finding,
)
from backend.verification.sqli_error_based import (
    evaluate_error_based_sqli,
)
from backend.verification.sqli_response import ResponseObservation
from backend.verification.sqli_time_based import (
    verify_sqli_time_based,
)
from backend.verification.sqli_time_based_context import (
    build_sqli_time_based_context,
)
from backend.verification.sqli_timing import (
    TimingSample,
    evaluate_trial_validity,
)
from backend.verification.sqli_union_based import (
    evaluate_union_based_sqli,
)


def finalize_error_based_sqli_verification(
    *,
    finding: NormalizedFinding,
    baseline_responses: list[ResponseObservation],
    verification_responses: list[ResponseObservation],
    parameter_dependency_established: bool,
    scanner_evidence_agrees: bool = False,
    baseline_db_error_explains_signal: bool = False,
    safe_parameter_handling_established: bool = False,
    controlled_non_sql_explanation_established: bool = False,
) -> VerifiedFinding:
    _require_sqli(finding)

    evaluation = evaluate_error_based_sqli(
        baseline_responses=baseline_responses,
        verification_responses=verification_responses,
        parameter_dependency_established=(
            parameter_dependency_established
        ),
        scanner_evidence_agrees=scanner_evidence_agrees,
        baseline_db_error_explains_signal=(
            baseline_db_error_explains_signal
        ),
        safe_parameter_handling_established=(
            safe_parameter_handling_established
        ),
        controlled_non_sql_explanation_established=(
            controlled_non_sql_explanation_established
        ),
    )

    _save_evidence(
        finding=finding,
        subtype="ERROR_BASED",
        evidence=evaluation.evidence,
    )

    return build_verified_finding(
        finding=finding,
        decision=evaluation.decision,
        verification_method="sqli_error_based_rule_v1",
        response_available=bool(verification_responses),
    )


def finalize_boolean_based_sqli_verification(
    *,
    finding: NormalizedFinding,
    baseline_responses: list[ResponseObservation],
    comparisons: list[BooleanComparisonTrial],
    parameter_dependency_established: bool,
    scanner_true_marker: str | None = None,
    scanner_false_marker: str | None = None,
    scanner_evidence_agrees: bool = False,
    control_equivalence_established: bool = False,
    safe_parameter_handling_established: bool = False,
    safe_non_sql_explanation_established: bool = False,
) -> VerifiedFinding:
    _require_sqli(finding)

    evaluation = evaluate_boolean_based_sqli(
        baseline_responses=baseline_responses,
        comparisons=comparisons,
        parameter_dependency_established=(
            parameter_dependency_established
        ),
        scanner_true_marker=scanner_true_marker,
        scanner_false_marker=scanner_false_marker,
        scanner_evidence_agrees=scanner_evidence_agrees,
        control_equivalence_established=(
            control_equivalence_established
        ),
        safe_parameter_handling_established=(
            safe_parameter_handling_established
        ),
        safe_non_sql_explanation_established=(
            safe_non_sql_explanation_established
        ),
    )

    _save_evidence(
        finding=finding,
        subtype="BOOLEAN_BASED",
        evidence=evaluation.evidence,
    )

    return build_verified_finding(
        finding=finding,
        decision=evaluation.decision,
        verification_method="sqli_boolean_based_rule_v1",
        response_available=bool(comparisons),
    )


def finalize_time_based_sqli_verification(
    *,
    finding: NormalizedFinding,
    replay_result: ReplayResult,
    baseline_samples: list[TimingSample],
    verification_samples: list[TimingSample],
    external_timing_interference_observed: bool = False,
    scanner_evidence_agrees: bool = False,
    verification_confidence: float | None = None,
    credible_network_or_server_explanation: bool | None = None,
) -> VerifiedFinding:
    """
    Build and classify TIME_BASED SQLi evidence.

    verification_confidence is accepted only so older internal callers
    do not crash while this batch is applied. It is deliberately not
    used. Confidence is now derived from the frozen SQLi policy.

    credible_network_or_server_explanation is the previous internal
    name. When supplied, it is treated as observed external timing
    interference. Missing infrastructure telemetry is not itself an
    inconclusive condition.
    """

    _require_sqli(finding)

    if credible_network_or_server_explanation is not None:
        external_timing_interference_observed = (
            credible_network_or_server_explanation
        )

    context = build_sqli_time_based_context(
        baseline_samples=baseline_samples,
        verification_samples=verification_samples,
        credible_network_or_server_explanation=(
            external_timing_interference_observed
        ),
        verification_confidence=0.0,
    )

    verified = verify_sqli_time_based(
        finding=finding,
        replay_result=replay_result,
        context=context,
        scanner_evidence_agrees=scanner_evidence_agrees,
    )

    _save_time_based_evidence(
        finding=finding,
        context=context,
        baseline_samples=baseline_samples,
        verification_samples=verification_samples,
    )

    return verified


def finalize_union_based_sqli_verification(
    *,
    finding: NormalizedFinding,
    baseline_responses: list[ResponseObservation],
    verification_responses: list[ResponseObservation],
    union_technique_identified: bool,
    parameter_dependency_established: bool,
    scanner_marker: str | None = None,
    scanner_db_derived_output: str | None = None,
    scanner_establishes_db_origin: bool = False,
    scanner_evidence_agrees: bool = False,
    control_equivalence_established: bool = False,
    safe_parameter_handling_established: bool = False,
    safe_non_union_explanation_established: bool = False,
) -> VerifiedFinding:
    _require_sqli(finding)

    evaluation = evaluate_union_based_sqli(
        baseline_responses=baseline_responses,
        verification_responses=verification_responses,
        union_technique_identified=(
            union_technique_identified
        ),
        parameter_dependency_established=(
            parameter_dependency_established
        ),
        scanner_marker=scanner_marker,
        scanner_db_derived_output=(
            scanner_db_derived_output
        ),
        scanner_establishes_db_origin=(
            scanner_establishes_db_origin
        ),
        scanner_evidence_agrees=scanner_evidence_agrees,
        control_equivalence_established=(
            control_equivalence_established
        ),
        safe_parameter_handling_established=(
            safe_parameter_handling_established
        ),
        safe_non_union_explanation_established=(
            safe_non_union_explanation_established
        ),
    )

    _save_evidence(
        finding=finding,
        subtype="UNION_BASED",
        evidence=evaluation.evidence,
    )

    return build_verified_finding(
        finding=finding,
        decision=evaluation.decision,
        verification_method="sqli_union_based_rule_v1",
        response_available=bool(verification_responses),
    )


def _require_sqli(
    finding: NormalizedFinding,
) -> None:
    if finding.vulnerability.category != "SQLI":
        raise ValueError(
            "SQLi verification service received a non-SQLI finding"
        )


def _save_evidence(
    *,
    finding: NormalizedFinding,
    subtype: str,
    evidence,
) -> None:
    save_sqli_verification_evidence(
        scan_id=finding.scan_id,
        finding_id=finding.finding_id,
        subtype=subtype,
        evidence=_to_plain_data(evidence),
    )


def _save_time_based_evidence(
    *,
    finding: NormalizedFinding,
    context,
    baseline_samples: list[TimingSample],
    verification_samples: list[TimingSample],
) -> None:
    baseline_response_times = [
        sample.response_time_ms
        for sample in baseline_samples
    ]

    verification_response_times = [
        sample.response_time_ms
        for sample in verification_samples
    ]

    per_trial_delay = []
    per_trial_delay_pass = []

    baseline_statistics = context.baseline_statistics

    baseline_median = (
        baseline_statistics.median_ms
        if baseline_statistics is not None
        else None
    )
    baseline_mad = (
        baseline_statistics.mad_ms
        if baseline_statistics is not None
        else None
    )
    baseline_variation_ratio = (
        baseline_statistics.variation_ratio
        if baseline_statistics is not None
        else None
    )

    valid_verification_samples = [
        sample
        for sample in verification_samples
        if evaluate_trial_validity(sample).valid
    ][:3]

    threshold = context.aggregate_delay_threshold_ms

    if baseline_median is not None and threshold is not None:
        for sample in valid_verification_samples:
            delay = (
                sample.response_time_ms
                - baseline_median
            )
            per_trial_delay.append(delay)

            ratio = (
                sample.response_time_ms
                / baseline_median
                if baseline_median
                else float("inf")
            )

            per_trial_delay_pass.append(
                delay >= threshold
                and ratio >= 2.0
            )

    evidence = {
        "baseline_response_times": baseline_response_times,
        "verification_response_times": (
            verification_response_times
        ),
        "baseline_median": baseline_median,
        "baseline_MAD": baseline_mad,
        "baseline_variation_ratio": baseline_variation_ratio,
        "timing_delta_ms": (
            context.verification_statistics.timing_delta_ms
            if context.verification_statistics is not None
            else None
        ),
        "timing_ratio": (
            context.verification_statistics.timing_ratio
            if context.verification_statistics is not None
            else None
        ),
        "per_trial_delay": per_trial_delay,
        "per_trial_delay_pass": per_trial_delay_pass,
        "external_timing_interference_observed": (
            context.credible_network_or_server_explanation
        ),
    }

    save_sqli_verification_evidence(
        scan_id=finding.scan_id,
        finding_id=finding.finding_id,
        subtype="TIME_BASED",
        evidence=evidence,
    )


def _to_plain_data(value):
    if isinstance(value, Enum):
        return value.value

    if is_dataclass(value):
        return _to_plain_data(
            asdict(value)
        )

    if isinstance(value, dict):
        return {
            str(key): _to_plain_data(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [
            _to_plain_data(item)
            for item in value
        ]

    return value
