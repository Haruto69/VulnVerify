import hashlib
from dataclasses import dataclass

from backend.verification.sqli_contract import (
    SqliDecision,
    SqliReasonCode,
    SqliVerificationStatus,
    controlled_false_positive_confidence,
    inconclusive_decision,
    repeated_absence_false_positive_confidence,
    safe_handling_false_positive_confidence,
    true_positive_confidence,
)
from backend.verification.sqli_error_signatures import (
    find_database_error_matches,
)
from backend.verification.sqli_response import (
    ResponseObservation,
    evaluate_non_time_baseline,
)


MYSQL_COLUMN_COUNT_SIGNATURE = "MYSQL_COLUMN_COUNT_ERROR"


@dataclass(frozen=True)
class UnionBasedEvidence:
    union_marker: str | None
    marker_source: str | None
    marker_present_baseline: bool | None
    marker_present_verification: tuple[bool, ...]
    db_derived_output: str | None
    db_derived_output_location: str | None
    output_fingerprint: str | None
    output_difference: bool | None
    column_count_error_signature: str | None


@dataclass(frozen=True)
class UnionBasedEvaluation:
    decision: SqliDecision
    evidence: UnionBasedEvidence


def evaluate_union_based_sqli(
    *,
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
) -> UnionBasedEvaluation:
    baseline = evaluate_non_time_baseline(
        baseline_responses
    )

    valid_verification = [
        response
        for response in verification_responses
        if response.valid
    ][:3]

    selected_baseline = [
        baseline_responses[index]
        for index in baseline.selected_indices
    ]

    marker_present_baseline = None
    marker_presence: tuple[bool, ...] = ()

    if scanner_marker is not None:
        marker_present_baseline = any(
            scanner_marker in response.body
            for response in selected_baseline
        )
        marker_presence = tuple(
            scanner_marker in response.body
            for response in valid_verification
        )

    output_present_baseline = None
    output_presence: tuple[bool, ...] = ()

    if scanner_db_derived_output is not None:
        output_present_baseline = any(
            scanner_db_derived_output in response.body
            for response in selected_baseline
        )
        output_presence = tuple(
            scanner_db_derived_output in response.body
            for response in valid_verification
        )

    column_count_error_present = any(
        any(
            match.signature_id == MYSQL_COLUMN_COUNT_SIGNATURE
            for match in find_database_error_matches(response.body)
        )
        for response in valid_verification
    )

    evidence = UnionBasedEvidence(
        union_marker=scanner_marker,
        marker_source=(
            "scanner"
            if scanner_marker is not None
            else None
        ),
        marker_present_baseline=marker_present_baseline,
        marker_present_verification=marker_presence,
        db_derived_output=scanner_db_derived_output,
        db_derived_output_location=(
            "response_body"
            if scanner_db_derived_output is not None
            else None
        ),
        output_fingerprint=(
            hashlib.sha256(
                scanner_db_derived_output.encode("utf-8")
            ).hexdigest()
            if scanner_db_derived_output is not None
            else None
        ),
        output_difference=(
            not output_present_baseline
            if output_present_baseline is not None
            else None
        ),
        column_count_error_signature=(
            MYSQL_COLUMN_COUNT_SIGNATURE
            if column_count_error_present
            else None
        ),
    )

    if not baseline.stable:
        return UnionBasedEvaluation(
            decision=inconclusive_decision(
                SqliReasonCode.INC_UNSTABLE_BASELINE,
                "A stable non-time SQLi baseline could not be established.",
            ),
            evidence=evidence,
        )

    if not union_technique_identified:
        return UnionBasedEvaluation(
            decision=inconclusive_decision(
                SqliReasonCode.INC_INSUFFICIENT_SCANNER_EVIDENCE,
                "The scanner evidence does not establish a UNION_BASED technique.",
            ),
            evidence=evidence,
        )

    if len(valid_verification) < 3:
        return UnionBasedEvaluation(
            decision=inconclusive_decision(
                SqliReasonCode.INC_INSUFFICIENT_VALID_TRIALS,
                "Fewer than three valid UNION_BASED verification trials were available.",
            ),
            evidence=evidence,
        )

    if control_equivalence_established:
        return UnionBasedEvaluation(
            decision=SqliDecision(
                status=SqliVerificationStatus.FALSE_POSITIVE,
                confidence=controlled_false_positive_confidence(),
                reason_code=(
                    SqliReasonCode.FP_UNION_CONTROL_EQUIVALENCE
                ),
                reason=(
                    "Controlled evidence establishes that the scanner signal is normal and not UNION-specific."
                ),
                indicators=("union_control_equivalence",),
            ),
            evidence=evidence,
        )

    marker_reproduced = (
        scanner_marker is not None
        and marker_present_baseline is False
        and sum(marker_presence) >= 2
        and parameter_dependency_established
    )

    if marker_reproduced:
        return UnionBasedEvaluation(
            decision=SqliDecision(
                status=SqliVerificationStatus.TRUE_POSITIVE,
                confidence=true_positive_confidence(
                    scanner_evidence_agrees=(
                        scanner_evidence_agrees
                    )
                ),
                reason_code=SqliReasonCode.TP_UNION_SCANNER_MARKER,
                reason=(
                    "The exact scanner-provided UNION marker was absent from the baseline and reproduced in at least two of three valid verification trials with parameter dependency established."
                ),
                indicators=(
                    "scanner_union_marker",
                    "union_marker_reproduced_2_of_3",
                    "parameter_dependency_established",
                ),
            ),
            evidence=evidence,
        )

    output_reproduced = (
        scanner_db_derived_output is not None
        and scanner_establishes_db_origin
        and output_present_baseline is False
        and sum(output_presence) >= 2
        and parameter_dependency_established
    )

    if output_reproduced:
        return UnionBasedEvaluation(
            decision=SqliDecision(
                status=SqliVerificationStatus.TRUE_POSITIVE,
                confidence=true_positive_confidence(
                    scanner_evidence_agrees=(
                        scanner_evidence_agrees
                    )
                ),
                reason_code=(
                    SqliReasonCode.TP_UNION_DATABASE_DERIVED_OUTPUT
                ),
                reason=(
                    "Scanner-established database-derived UNION output was absent from the baseline and reproduced in at least two of three valid trials with parameter dependency established."
                ),
                indicators=(
                    "database_derived_union_output",
                    "union_output_reproduced_2_of_3",
                    "parameter_dependency_established",
                ),
            ),
            evidence=evidence,
        )

    if safe_parameter_handling_established:
        return UnionBasedEvaluation(
            decision=SqliDecision(
                status=SqliVerificationStatus.FALSE_POSITIVE,
                confidence=safe_handling_false_positive_confidence(),
                reason_code=SqliReasonCode.FP_SAFE_PARAMETER_HANDLING,
                reason=(
                    "Deterministic safe or non-SQL parameter handling disproves the scanner's UNION SQLi claim."
                ),
                indicators=("safe_parameter_handling_established",),
            ),
            evidence=evidence,
        )

    if safe_non_union_explanation_established:
        return UnionBasedEvaluation(
            decision=SqliDecision(
                status=SqliVerificationStatus.FALSE_POSITIVE,
                confidence=repeated_absence_false_positive_confidence(),
                reason_code=SqliReasonCode.FP_NO_UNION_OUTPUT,
                reason=(
                    "All required UNION replays completed without UNION-specific output and a controlled normal or non-UNION explanation was established."
                ),
                indicators=("controlled_non_union_explanation",),
            ),
            evidence=evidence,
        )

    if column_count_error_present:
        return UnionBasedEvaluation(
            decision=inconclusive_decision(
                SqliReasonCode.INC_AMBIGUOUS_UNION_OUTPUT,
                "A MySQL column-count error is supporting DATABASE_ERROR evidence only and does not prove successful UNION execution.",
                indicators=(MYSQL_COLUMN_COUNT_SIGNATURE,),
            ),
            evidence=evidence,
        )

    if scanner_marker is None and scanner_db_derived_output is None:
        return UnionBasedEvaluation(
            decision=inconclusive_decision(
                SqliReasonCode.INC_UNSUPPORTED_CONFIRMATION_PATH,
                "Scanner-provided UNION marker or established database-derived output is unavailable, and generated UNION confirmation is disabled in v1.",
            ),
            evidence=evidence,
        )

    return UnionBasedEvaluation(
        decision=inconclusive_decision(
            SqliReasonCode.INC_AMBIGUOUS_UNION_OUTPUT,
            "The available UNION evidence does not satisfy the deterministic TRUE_POSITIVE or controlled FALSE_POSITIVE contract.",
        ),
        evidence=evidence,
    )
