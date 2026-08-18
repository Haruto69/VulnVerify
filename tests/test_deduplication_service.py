import pytest

from backend.models.normalized_finding import NormalizedFinding
from backend.models.verified_finding import VerifiedFinding
from backend.services.deduplication_service import (
    group_duplicate_findings,
)


def make_normalized(
    finding_id: str,
    scan_id: str = "scan-001",
    category: str = "SQLI",
    normalized_url: str = "http://example.test/item",
    parameter: str | None = "id",
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
            "category": category,
            "subtype": None,
            "raw_severity": "High",
            "normalized_severity": "HIGH",
            "raw_confidence": "2",
            "normalized_confidence": "UNKNOWN",
            "cwe": "CWE-89",
        },
        target={
            "url": f"{normalized_url}?id=1",
            "normalized_url": normalized_url,
            "host": "example.test",
            "path": "/item",
            "parameter": parameter,
            "parameter_location": "QUERY",
        },
        original_test={
            "payload": "'",
            "evidence": "SQL syntax error",
        },
        request={
            "method": "GET",
            "url": f"{normalized_url}?id=1",
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
    category: str = "SQLI",
    normalized_url: str = "http://example.test/item",
    parameter: str | None = "id",
    status: str = "TRUE_POSITIVE",
    confidence: float = 0.9,
):
    return (
        make_normalized(
            finding_id=finding_id,
            scan_id=scan_id,
            category=category,
            normalized_url=normalized_url,
            parameter=parameter,
        ),
        make_verified(
            finding_id=finding_id,
            status=status,
            confidence=confidence,
        ),
    )


def test_identical_verified_findings_are_grouped():
    pair_a = make_pair(finding_id="f-a")
    pair_b = make_pair(finding_id="f-b")

    groups = group_duplicate_findings(
        findings=[pair_a, pair_b]
    )

    assert len(groups) == 1
    assert len(groups[0].members) == 2


def test_different_categories_are_not_grouped():
    pair_a = make_pair(finding_id="f-a", category="SQLI")
    pair_b = make_pair(finding_id="f-b", category="XSS")

    groups = group_duplicate_findings(
        findings=[pair_a, pair_b]
    )

    assert len(groups) == 2


def test_different_normalized_urls_are_not_grouped():
    pair_a = make_pair(
        finding_id="f-a",
        normalized_url="http://example.test/item",
    )
    pair_b = make_pair(
        finding_id="f-b",
        normalized_url="http://example.test/other",
    )

    groups = group_duplicate_findings(
        findings=[pair_a, pair_b]
    )

    assert len(groups) == 2


def test_different_parameters_are_not_grouped():
    pair_a = make_pair(finding_id="f-a", parameter="id")
    pair_b = make_pair(finding_id="f-b", parameter="name")

    groups = group_duplicate_findings(
        findings=[pair_a, pair_b]
    )

    assert len(groups) == 2


def test_none_parameter_is_a_valid_group_key():
    pair_a = make_pair(finding_id="f-a", parameter=None)
    pair_b = make_pair(finding_id="f-b", parameter=None)

    groups = group_duplicate_findings(
        findings=[pair_a, pair_b]
    )

    assert len(groups) == 1
    assert groups[0].parameter is None
    assert len(groups[0].members) == 2


def test_single_finding_produces_single_group():
    pair_a = make_pair(finding_id="f-a")

    groups = group_duplicate_findings(findings=[pair_a])

    assert len(groups) == 1
    assert len(groups[0].members) == 1
    assert groups[0].members[0].finding_id == "f-a"


def test_empty_input_produces_no_groups():
    groups = group_duplicate_findings(findings=[])

    assert groups == []


def test_mixed_scan_ids_are_rejected():
    pair_a = make_pair(finding_id="f-a", scan_id="scan-001")
    pair_b = make_pair(finding_id="f-b", scan_id="scan-002")

    with pytest.raises(ValueError):
        group_duplicate_findings(
            findings=[pair_a, pair_b]
        )


def test_group_preserves_member_finding_ids():
    pair_a = make_pair(finding_id="f-a")
    pair_b = make_pair(finding_id="f-b")
    pair_c = make_pair(finding_id="f-c")

    groups = group_duplicate_findings(
        findings=[pair_a, pair_b, pair_c]
    )

    assert len(groups) == 1

    member_ids = {
        member.finding_id
        for member in groups[0].members
    }

    assert member_ids == {"f-a", "f-b", "f-c"}


def test_group_preserves_existing_classifications():
    pair_a = make_pair(
        finding_id="f-a",
        status="TRUE_POSITIVE",
        confidence=0.9,
    )
    pair_b = make_pair(
        finding_id="f-b",
        status="INCONCLUSIVE",
        confidence=0.0,
    )

    groups = group_duplicate_findings(
        findings=[pair_a, pair_b]
    )

    assert len(groups) == 1

    members_by_id = {
        member.finding_id: member
        for member in groups[0].members
    }

    assert (
        members_by_id["f-a"].classification.status
        == "TRUE_POSITIVE"
    )
    assert members_by_id["f-a"].classification.confidence == 0.9

    assert (
        members_by_id["f-b"].classification.status
        == "INCONCLUSIVE"
    )
    assert members_by_id["f-b"].classification.confidence == 0.0

    # No combined/merged verdict is ever produced.
    assert not hasattr(groups[0], "classification")
    assert not hasattr(groups[0], "status")
    assert not hasattr(groups[0], "confidence")


def test_inputs_are_not_mutated():
    normalized_a, verified_a = make_pair(finding_id="f-a")
    normalized_b, verified_b = make_pair(finding_id="f-b")

    normalized_a_before = normalized_a.model_copy(deep=True)
    verified_a_before = verified_a.model_copy(deep=True)
    normalized_b_before = normalized_b.model_copy(deep=True)
    verified_b_before = verified_b.model_copy(deep=True)

    group_duplicate_findings(
        findings=[
            (normalized_a, verified_a),
            (normalized_b, verified_b),
        ]
    )

    assert normalized_a == normalized_a_before
    assert verified_a == verified_a_before
    assert normalized_b == normalized_b_before
    assert verified_b == verified_b_before


def test_mismatched_finding_id_pairing_is_rejected():
    normalized = make_normalized(finding_id="f-a")
    verified = make_verified(finding_id="f-different")

    with pytest.raises(ValueError):
        group_duplicate_findings(
            findings=[(normalized, verified)]
        )


def test_group_ordering_is_deterministic():
    pair_a = make_pair(
        finding_id="f-a",
        normalized_url="http://example.test/first",
    )
    pair_b = make_pair(
        finding_id="f-b",
        normalized_url="http://example.test/second",
    )
    pair_c = make_pair(
        finding_id="f-c",
        normalized_url="http://example.test/first",
    )

    groups = group_duplicate_findings(
        findings=[pair_a, pair_b, pair_c]
    )

    assert [g.normalized_url for g in groups] == [
        "http://example.test/first",
        "http://example.test/second",
    ]

    # Re-running with the same input order produces the same output
    # order.
    groups_again = group_duplicate_findings(
        findings=[pair_a, pair_b, pair_c]
    )

    assert [g.normalized_url for g in groups] == [
        g.normalized_url for g in groups_again
    ]
