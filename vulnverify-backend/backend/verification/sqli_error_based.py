from collections import Counter
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
    DatabaseErrorMatch,
    find_database_error_matches,
)
from backend.verification.sqli_response import (
    ResponseObservation,
    evaluate_non_time_baseline,
)


@dataclass(frozen=True)
class ErrorBasedEvidence:
    error_signature_id: str | None
    error_db_family: str | None
    error_match_text: str | None
    error_match_location: str | None
    error_match_count: int
    baseline_match_count: int
    verification_matches: tuple[
        tuple[DatabaseErrorMatch, ...], ...
    ]


@dataclass(frozen=True)
class ErrorBasedEvaluation:
    decision: SqliDecision
    evidence: ErrorBasedEvidence


def evaluate_error_based_sqli(
    *,
    baseline_responses: list[ResponseObservation],
    verification_responses: list[ResponseObservation],
    parameter_dependency_established: bool,
    scanner_evidence_agrees: bool = False,
    baseline_db_error_explains_signal: bool = False,
    safe_parameter_handling_established: bool = False,
    controlled_non_sql_explanation_established: bool = False,
) -> ErrorBasedEvaluation:
    baseline = evaluate_non_time_baseline(
        baseline_responses
    )

    baseline_matches = _matches_for_selected_baseline(
        baseline_responses,
        baseline.selected_indices,
    )

    valid_verification = [
        response
        for response in verification_responses
        if response.valid
    ][:3]

    verification_matches = tuple(
        find_database_error_matches(response.body)
        for response in valid_verification
    )

    evidence = _build_evidence(
        baseline_matches=baseline_matches,
        verification_matches=verification_matches,
    )

    if not baseline.stable:
        return ErrorBasedEvaluation(
            decision=inconclusive_decision(
                SqliReasonCode.INC_UNSTABLE_BASELINE,
                "A stable non-time SQLi baseline could not be established.",
            ),
            evidence=evidence,
        )

    if len(valid_verification) < 3:
        return ErrorBasedEvaluation(
            decision=inconclusive_decision(
                SqliReasonCode.INC_INSUFFICIENT_VALID_TRIALS,
                "Fewer than three valid ERROR_BASED verification trials were available.",
            ),
            evidence=evidence,
        )

    if baseline_matches:
        if baseline_db_error_explains_signal:
            return ErrorBasedEvaluation(
                decision=SqliDecision(
                    status=SqliVerificationStatus.FALSE_POSITIVE,
                    confidence=controlled_false_positive_confidence(),
                    reason_code=SqliReasonCode.FP_BASELINE_DB_ERROR,
                    reason=(
                        "The same database-error behavior is established "
                        "in the controlled baseline and explains the scanner signal."
                    ),
                    indicators=("database_error_present_in_baseline",),
                ),
                evidence=evidence,
            )

        return ErrorBasedEvaluation(
            decision=inconclusive_decision(
                SqliReasonCode.INC_AMBIGUOUS_DATABASE_ERROR,
                "A supported database error is already present in the baseline, so SQL parameter attribution is ambiguous.",
                indicators=("database_error_present_in_baseline",),
            ),
            evidence=evidence,
        )

    reproduced_signature = _reproduced_signature(
        verification_matches
    )

    if (
        reproduced_signature is not None
        and parameter_dependency_established
    ):
        return ErrorBasedEvaluation(
            decision=SqliDecision(
                status=SqliVerificationStatus.TRUE_POSITIVE,
                confidence=true_positive_confidence(
                    scanner_evidence_agrees=(
                        scanner_evidence_agrees
                    )
                ),
                reason_code=SqliReasonCode.TP_DATABASE_ERROR,
                reason=(
                    "A supported database-specific error absent from the baseline was reproduced in at least two of the first three valid trials and is attributable to the tested parameter."
                ),
                indicators=(
                    "database_error_absent_from_baseline",
                    "database_error_reproduced_2_of_3",
                    "parameter_dependency_established",
                    reproduced_signature,
                ),
            ),
            evidence=evidence,
        )

    if safe_parameter_handling_established:
        return ErrorBasedEvaluation(
            decision=SqliDecision(
                status=SqliVerificationStatus.FALSE_POSITIVE,
                confidence=safe_handling_false_positive_confidence(),
                reason_code=SqliReasonCode.FP_SAFE_PARAMETER_HANDLING,
                reason=(
                    "Deterministic safe or non-SQL parameter handling explains the scanner signal."
                ),
                indicators=("safe_parameter_handling_established",),
            ),
            evidence=evidence,
        )

    if controlled_non_sql_explanation_established:
        return ErrorBasedEvaluation(
            decision=SqliDecision(
                status=SqliVerificationStatus.FALSE_POSITIVE,
                confidence=repeated_absence_false_positive_confidence(),
                reason_code=SqliReasonCode.FP_NO_SQL_DATABASE_ERROR,
                reason=(
                    "Required replay completed without reproducible SQL database-error behavior and a controlled non-SQL explanation was established."
                ),
                indicators=("controlled_non_sql_explanation",),
            ),
            evidence=evidence,
        )

    return ErrorBasedEvaluation(
        decision=inconclusive_decision(
            SqliReasonCode.INC_AMBIGUOUS_DATABASE_ERROR,
            "The available ERROR_BASED evidence does not satisfy the deterministic TRUE_POSITIVE or controlled FALSE_POSITIVE contract.",
        ),
        evidence=evidence,
    )


def _matches_for_selected_baseline(
    baseline_responses: list[ResponseObservation],
    selected_indices: tuple[int, ...],
) -> tuple[DatabaseErrorMatch, ...]:
    matches: list[DatabaseErrorMatch] = []

    for index in selected_indices:
        matches.extend(
            find_database_error_matches(
                baseline_responses[index].body
            )
        )

    return tuple(matches)


def _reproduced_signature(
    verification_matches: tuple[
        tuple[DatabaseErrorMatch, ...], ...
    ],
) -> str | None:
    signature_presence = Counter()

    for trial_matches in verification_matches[:3]:
        trial_ids = {
            match.signature_id
            for match in trial_matches
        }

        for signature_id in trial_ids:
            signature_presence[signature_id] += 1

    for signature_id, count in signature_presence.items():
        if count >= 2:
            return signature_id

    return None


def _build_evidence(
    *,
    baseline_matches: tuple[DatabaseErrorMatch, ...],
    verification_matches: tuple[
        tuple[DatabaseErrorMatch, ...], ...
    ],
) -> ErrorBasedEvidence:
    flattened = [
        match
        for trial in verification_matches
        for match in trial
    ]

    primary = flattened[0] if flattened else None

    return ErrorBasedEvidence(
        error_signature_id=(
            primary.signature_id
            if primary is not None
            else None
        ),
        error_db_family=(
            primary.db_family.value
            if primary is not None
            else None
        ),
        error_match_text=(
            primary.matched_text
            if primary is not None
            else None
        ),
        error_match_location=(
            primary.location
            if primary is not None
            else None
        ),
        error_match_count=len(flattened),
        baseline_match_count=len(baseline_matches),
        verification_matches=verification_matches,
    )
