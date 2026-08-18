from dataclasses import dataclass
from enum import Enum

from backend.models.normalized_finding import NormalizedFinding
from backend.models.verified_finding import VerifiedFinding


class SqliVerificationStatus(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


class SqliEvidenceStrength(str, Enum):
    STRONG = "STRONG"
    SUPPORTING = "SUPPORTING"
    NONE = "NONE"


class SqliReasonCode(str, Enum):
    TP_DATABASE_ERROR = "TP_DATABASE_ERROR"
    TP_BOOLEAN_RESPONSE_DIFFERENCE = (
        "TP_BOOLEAN_RESPONSE_DIFFERENCE"
    )
    TP_REPRODUCIBLE_TIMING_DIFFERENCE = (
        "TP_REPRODUCIBLE_TIMING_DIFFERENCE"
    )
    TP_UNION_DATABASE_DERIVED_OUTPUT = (
        "TP_UNION_DATABASE_DERIVED_OUTPUT"
    )
    TP_UNION_SCANNER_MARKER = "TP_UNION_SCANNER_MARKER"

    FP_BASELINE_DB_ERROR = "FP_BASELINE_DB_ERROR"
    FP_NO_SQL_DATABASE_ERROR = "FP_NO_SQL_DATABASE_ERROR"
    FP_SAFE_PARAMETER_HANDLING = "FP_SAFE_PARAMETER_HANDLING"
    FP_NO_BOOLEAN_DIFFERENCE = "FP_NO_BOOLEAN_DIFFERENCE"
    FP_BOOLEAN_CONTROL_EQUIVALENCE = (
        "FP_BOOLEAN_CONTROL_EQUIVALENCE"
    )
    FP_NO_TIMING_DIFFERENCE = "FP_NO_TIMING_DIFFERENCE"
    FP_NORMAL_TIMING_BEHAVIOR = "FP_NORMAL_TIMING_BEHAVIOR"
    FP_NO_UNION_OUTPUT = "FP_NO_UNION_OUTPUT"
    FP_UNION_CONTROL_EQUIVALENCE = (
        "FP_UNION_CONTROL_EQUIVALENCE"
    )

    INC_AUTHENTICATION_FAILED = "INC_AUTHENTICATION_FAILED"
    INC_SESSION_EXPIRED = "INC_SESSION_EXPIRED"
    INC_WAF_BLOCKED = "INC_WAF_BLOCKED"
    INC_RATE_LIMITED = "INC_RATE_LIMITED"
    INC_ENDPOINT_UNAVAILABLE = "INC_ENDPOINT_UNAVAILABLE"
    INC_PARAMETER_UNKNOWN = "INC_PARAMETER_UNKNOWN"
    INC_PARAMETER_LOCATION_UNKNOWN = (
        "INC_PARAMETER_LOCATION_UNKNOWN"
    )
    INC_REQUEST_NOT_REPRODUCIBLE = (
        "INC_REQUEST_NOT_REPRODUCIBLE"
    )
    INC_UNSTABLE_BASELINE = "INC_UNSTABLE_BASELINE"
    INC_UNSTABLE_TIMING = "INC_UNSTABLE_TIMING"
    INC_INSUFFICIENT_VALID_TRIALS = (
        "INC_INSUFFICIENT_VALID_TRIALS"
    )
    INC_INSUFFICIENT_SCANNER_EVIDENCE = (
        "INC_INSUFFICIENT_SCANNER_EVIDENCE"
    )
    INC_UNSUPPORTED_CONFIRMATION_PATH = (
        "INC_UNSUPPORTED_CONFIRMATION_PATH"
    )
    INC_AMBIGUOUS_DATABASE_ERROR = (
        "INC_AMBIGUOUS_DATABASE_ERROR"
    )
    INC_AMBIGUOUS_BOOLEAN_RESPONSE = (
        "INC_AMBIGUOUS_BOOLEAN_RESPONSE"
    )
    INC_AMBIGUOUS_UNION_OUTPUT = (
        "INC_AMBIGUOUS_UNION_OUTPUT"
    )
    INC_EXTERNAL_TIMING_EXPLANATION = (
        "INC_EXTERNAL_TIMING_EXPLANATION"
    )
    INC_NETWORK_FAILURE = "INC_NETWORK_FAILURE"
    INC_TIMEOUT = "INC_TIMEOUT"


@dataclass(frozen=True)
class SqliDecision:
    status: SqliVerificationStatus
    confidence: float
    reason_code: SqliReasonCode
    reason: str
    indicators: tuple[str, ...] = ()


def true_positive_confidence(
    *,
    scanner_evidence_agrees: bool = False,
    supporting_signal_weakened: bool = False,
) -> float:
    if supporting_signal_weakened:
        return 0.95

    if scanner_evidence_agrees:
        return 0.99

    return 0.98


def controlled_false_positive_confidence() -> float:
    return 0.97


def safe_handling_false_positive_confidence() -> float:
    return 0.96


def repeated_absence_false_positive_confidence() -> float:
    return 0.93


def inconclusive_confidence(
    reason_code: SqliReasonCode,
) -> float:
    if reason_code in {
        SqliReasonCode.INC_AUTHENTICATION_FAILED,
        SqliReasonCode.INC_SESSION_EXPIRED,
    }:
        return 0.25

    if reason_code in {
        SqliReasonCode.INC_WAF_BLOCKED,
        SqliReasonCode.INC_RATE_LIMITED,
        SqliReasonCode.INC_UNSTABLE_BASELINE,
        SqliReasonCode.INC_INSUFFICIENT_VALID_TRIALS,
    }:
        return 0.20

    if reason_code in {
        SqliReasonCode.INC_ENDPOINT_UNAVAILABLE,
        SqliReasonCode.INC_UNSTABLE_TIMING,
        SqliReasonCode.INC_AMBIGUOUS_DATABASE_ERROR,
        SqliReasonCode.INC_AMBIGUOUS_BOOLEAN_RESPONSE,
        SqliReasonCode.INC_AMBIGUOUS_UNION_OUTPUT,
        SqliReasonCode.INC_EXTERNAL_TIMING_EXPLANATION,
        SqliReasonCode.INC_NETWORK_FAILURE,
        SqliReasonCode.INC_TIMEOUT,
        SqliReasonCode.INC_INSUFFICIENT_SCANNER_EVIDENCE,
    }:
        return 0.15

    return 0.10


def inconclusive_decision(
    reason_code: SqliReasonCode,
    reason: str,
    *,
    indicators: tuple[str, ...] = (),
) -> SqliDecision:
    return SqliDecision(
        status=SqliVerificationStatus.INCONCLUSIVE,
        confidence=inconclusive_confidence(reason_code),
        reason_code=reason_code,
        reason=reason,
        indicators=indicators,
    )


def build_verified_finding(
    *,
    finding: NormalizedFinding,
    decision: SqliDecision,
    verification_method: str,
    response_available: bool = True,
) -> VerifiedFinding:
    request_reference = (
        f"{finding.finding_id}:{verification_method}:request"
    )

    response_reference = None

    if response_available:
        response_reference = (
            f"{finding.finding_id}:{verification_method}:response"
        )

    indicators = [
        decision.reason_code.value,
        *decision.indicators,
    ]

    return VerifiedFinding(
        finding_id=finding.finding_id,
        classification={
            "status": decision.status.value,
            "confidence": decision.confidence,
            "reason": decision.reason,
        },
        evidence={
            "indicators": indicators,
            "request_reference": request_reference,
            "response_reference": response_reference,
        },
        verification_method=verification_method,
    )
