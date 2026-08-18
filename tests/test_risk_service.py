import pytest

from backend.models.normalized_finding import NormalizedFinding
from backend.models.risk_assessment import PriorityLevel
from backend.models.verified_finding import VerifiedFinding
from backend.services.risk_service import assess_priorities


def make_normalized(
    finding_id: str,
    scan_id: str = "scan-001",
    severity: str = "HIGH",
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id=scan_id,
        finding_id=finding_id,
        source={
            "scanner": "ZAP",
            "scanner_finding_id": "40018",
            "original_name": "SQL Injection - MySQL",
        },
        vulnerability={
            "category": "SQLI",
            "subtype": None,
            "raw_severity": "High",
            "normalized_severity": severity,
            "raw_confidence": "2",
            "normalized_confidence": "UNKNOWN",
            "cwe": "CWE-89",
        },
        target={
            "url": "http://example.test/item?id=1",
            "normalized_url": "http://example.test/item",
            "host": "example.test",
            "path": "/item",
            "parameter": "id",
            "parameter_location": "QUERY",
        },
        original_test={
            "payload": "'",
            "evidence": "SQL syntax error",
        },
        request={
            "method": "GET",
            "url": "http://example.test/item?id=1",
            "path": "/item",
            "query_parameters": {"id": ["1"]},
            "headers": {},
            "cookies": {},
            "body": None,
            "content_type": None,
            "raw": None,
        },
        response=None,
        context={
            "authentication_required": "UNKNOWN",
            "session_required": "UNKNOWN",
        },
        references=[],
        metadata={},
    )


def make_verified(
    finding_id: str,
    status: str = "TRUE_POSITIVE",
    confidence: float = 0.9,
) -> VerifiedFinding:
    return VerifiedFinding(
        finding_id=finding_id,
        classification={
            "status": status,
            "confidence": confidence,
            "reason": "test result",
        },
        evidence={
            "indicators": [],
            "request_reference": None,
            "response_reference": None,
        },
        verification_method="sqli_time_based_rule_v1",
    )


def make_pair(
    finding_id: str,
    scan_id: str = "scan-001",
    severity: str = "HIGH",
    status: str = "TRUE_POSITIVE",
    confidence: float = 0.9,
):
    return (
        make_normalized(
            finding_id=finding_id,
            scan_id=scan_id,
            severity=severity,
        ),
        make_verified(
            finding_id=finding_id,
            status=status,
            confidence=confidence,
        ),
    )


@pytest.mark.parametrize(
    "severity,expected_priority",
    [
        ("CRITICAL", PriorityLevel.CRITICAL),
        ("HIGH", PriorityLevel.HIGH),
        ("MEDIUM", PriorityLevel.MEDIUM),
        ("LOW", PriorityLevel.LOW),
        ("INFORMATIONAL", PriorityLevel.INFORMATIONAL),
        ("UNKNOWN", PriorityLevel.MEDIUM),
    ],
)
def test_true_positive_maps_severity_directly(
    severity, expected_priority
):
    pair = make_pair(
        finding_id="f-a",
        severity=severity,
        status="TRUE_POSITIVE",
    )

    results = assess_priorities(findings=[pair])

    assert len(results) == 1
    assert results[0].priority == expected_priority


def test_false_positive_with_critical_severity_is_informational():
    pair = make_pair(
        finding_id="f-a",
        severity="CRITICAL",
        status="FALSE_POSITIVE",
    )

    results = assess_priorities(findings=[pair])

    assert results[0].priority == PriorityLevel.INFORMATIONAL


@pytest.mark.parametrize(
    "severity,expected_priority",
    [
        ("CRITICAL", PriorityLevel.MEDIUM),
        ("HIGH", PriorityLevel.MEDIUM),
        ("MEDIUM", PriorityLevel.MEDIUM),
        ("LOW", PriorityLevel.LOW),
        ("INFORMATIONAL", PriorityLevel.INFORMATIONAL),
    ],
)
def test_inconclusive_is_capped_at_medium(
    severity, expected_priority
):
    pair = make_pair(
        finding_id="f-a",
        severity=severity,
        status="INCONCLUSIVE",
    )

    results = assess_priorities(findings=[pair])

    assert results[0].priority == expected_priority


def test_confidence_does_not_affect_priority():
    high_confidence = make_pair(
        finding_id="f-a",
        severity="HIGH",
        status="TRUE_POSITIVE",
        confidence=0.99,
    )
    zero_confidence = make_pair(
        finding_id="f-b",
        severity="HIGH",
        status="TRUE_POSITIVE",
        confidence=0.0,
    )

    results = assess_priorities(
        findings=[high_confidence, zero_confidence]
    )

    assert (
        results[0].priority
        == results[1].priority
        == PriorityLevel.HIGH
    )


def test_empty_input_produces_no_results():
    assert assess_priorities(findings=[]) == []


def test_classification_status_and_scanner_severity_are_preserved():
    pair = make_pair(
        finding_id="f-a",
        scan_id="scan-xyz",
        severity="LOW",
        status="TRUE_POSITIVE",
    )

    results = assess_priorities(findings=[pair])

    assert results[0].verification_status == "TRUE_POSITIVE"
    assert results[0].scanner_severity == "LOW"
    assert results[0].finding_id == "f-a"
    assert results[0].scan_id == "scan-xyz"


def test_reason_is_populated_for_every_status():
    for status in (
        "TRUE_POSITIVE",
        "FALSE_POSITIVE",
        "INCONCLUSIVE",
    ):
        pair = make_pair(
            finding_id="f-a",
            severity="HIGH",
            status=status,
        )

        results = assess_priorities(findings=[pair])

        assert results[0].reason
