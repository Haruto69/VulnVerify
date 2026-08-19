from backend.models.verified_finding import (
    VerifiedFinding,
)
from backend.services.scan_service import (
    get_verified_finding,
    get_verified_findings,
    save_verified_finding,
)
from backend.storage.repository import (
    verified_findings,
)


def make_verified(
    finding_id: str,
    status: str,
) -> VerifiedFinding:
    return VerifiedFinding(
        finding_id=finding_id,
        classification={
            "status": status,
            "confidence": 0.95,
            "reason": "test result",
        },
        evidence={
            "indicators": [],
            "request_reference": None,
            "response_reference": None,
        },
        verification_method="csrf_rule_v1",
    )


def test_save_and_get_verified_finding():
    verified_findings.clear()

    finding = make_verified(
        finding_id="csrf-001",
        status="TRUE_POSITIVE",
    )

    save_verified_finding(
        scan_id="scan-001",
        finding=finding,
    )

    result = get_verified_finding(
        scan_id="scan-001",
        finding_id="csrf-001",
    )

    # Compared by value, not identity: verified_findings is now
    # backed by SQLite (backend/storage/collections.py), so a read
    # always returns a freshly-deserialized VerifiedFinding built from
    # stored data, never the exact object that was saved -- that was
    # never a real product guarantee, only an artifact of the old
    # in-memory dict implementation.
    assert result == finding


def test_list_verified_findings_for_scan():
    verified_findings.clear()

    first = make_verified(
        finding_id="csrf-001",
        status="TRUE_POSITIVE",
    )

    second = make_verified(
        finding_id="csrf-002",
        status="FALSE_POSITIVE",
    )

    save_verified_finding(
        scan_id="scan-001",
        finding=first,
    )

    save_verified_finding(
        scan_id="scan-001",
        finding=second,
    )

    results = get_verified_findings(
        "scan-001"
    )

    assert len(results) == 2

    assert {
        result.finding_id
        for result in results
    } == {
        "csrf-001",
        "csrf-002",
    }


def test_reverification_replaces_previous_result():
    verified_findings.clear()

    first = make_verified(
        finding_id="csrf-001",
        status="INCONCLUSIVE",
    )

    replacement = make_verified(
        finding_id="csrf-001",
        status="TRUE_POSITIVE",
    )

    save_verified_finding(
        scan_id="scan-001",
        finding=first,
    )

    save_verified_finding(
        scan_id="scan-001",
        finding=replacement,
    )

    results = get_verified_findings(
        "scan-001"
    )

    assert len(results) == 1

    assert (
        results[0].classification.status
        == "TRUE_POSITIVE"
    )