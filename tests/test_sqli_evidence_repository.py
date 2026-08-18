import pytest

from backend.storage.sqli_evidence_repository import (
    clear_sqli_verification_evidence,
    get_sqli_verification_evidence,
    save_sqli_verification_evidence,
)


@pytest.fixture(autouse=True)
def clean_evidence_store():
    clear_sqli_verification_evidence()
    yield
    clear_sqli_verification_evidence()


def test_saved_evidence_can_be_read_back():
    save_sqli_verification_evidence(
        scan_id="SCAN-1",
        finding_id="F-1",
        subtype="ERROR_BASED",
        evidence={"error_signature_id": "MYSQL_SYNTAX_001"},
    )

    stored = get_sqli_verification_evidence(
        scan_id="SCAN-1",
        finding_id="F-1",
    )

    assert stored == {
        "subtype": "ERROR_BASED",
        "evidence": {
            "error_signature_id": "MYSQL_SYNTAX_001"
        },
    }


def test_missing_finding_returns_none():
    assert (
        get_sqli_verification_evidence(
            scan_id="SCAN-1",
            finding_id="F-MISSING",
        )
        is None
    )


def test_missing_scan_returns_none():
    save_sqli_verification_evidence(
        scan_id="SCAN-1",
        finding_id="F-1",
        subtype="ERROR_BASED",
        evidence={},
    )

    assert (
        get_sqli_verification_evidence(
            scan_id="SCAN-OTHER",
            finding_id="F-1",
        )
        is None
    )


def test_findings_are_scoped_per_scan():
    save_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
        subtype="BOOLEAN_BASED",
        evidence={"value": "a"},
    )
    save_sqli_verification_evidence(
        scan_id="SCAN-B",
        finding_id="F-1",
        subtype="UNION_BASED",
        evidence={"value": "b"},
    )

    first = get_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
    )
    second = get_sqli_verification_evidence(
        scan_id="SCAN-B",
        finding_id="F-1",
    )

    assert first["subtype"] == "BOOLEAN_BASED"
    assert first["evidence"]["value"] == "a"
    assert second["subtype"] == "UNION_BASED"
    assert second["evidence"]["value"] == "b"


def test_multiple_findings_coexist_in_one_scan():
    save_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
        subtype="ERROR_BASED",
        evidence={"value": 1},
    )
    save_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-2",
        subtype="TIME_BASED",
        evidence={"value": 2},
    )

    assert (
        get_sqli_verification_evidence(
            scan_id="SCAN-A",
            finding_id="F-1",
        )["evidence"]["value"]
        == 1
    )
    assert (
        get_sqli_verification_evidence(
            scan_id="SCAN-A",
            finding_id="F-2",
        )["evidence"]["value"]
        == 2
    )


def test_resaving_replaces_the_previous_evidence():
    save_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
        subtype="ERROR_BASED",
        evidence={"attempt": 1},
    )
    save_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
        subtype="UNION_BASED",
        evidence={"attempt": 2},
    )

    stored = get_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
    )

    assert stored["subtype"] == "UNION_BASED"
    assert stored["evidence"] == {"attempt": 2}


def test_saved_evidence_is_deep_copied_on_write():
    payload = {"nested": {"values": [1, 2]}}

    save_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
        subtype="ERROR_BASED",
        evidence=payload,
    )

    payload["nested"]["values"].append(3)

    stored = get_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
    )

    assert stored["evidence"]["nested"]["values"] == [1, 2]


def test_read_evidence_is_deep_copied_on_read():
    save_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
        subtype="ERROR_BASED",
        evidence={"nested": {"values": [1, 2]}},
    )

    first = get_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
    )
    first["evidence"]["nested"]["values"].append(3)

    second = get_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
    )

    assert second["evidence"]["nested"]["values"] == [1, 2]


def test_clear_removes_everything():
    save_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
        subtype="ERROR_BASED",
        evidence={},
    )

    clear_sqli_verification_evidence()

    assert (
        get_sqli_verification_evidence(
            scan_id="SCAN-A",
            finding_id="F-1",
        )
        is None
    )


def test_empty_evidence_payload_is_stored():
    save_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
        subtype="TIME_BASED",
        evidence={},
    )

    stored = get_sqli_verification_evidence(
        scan_id="SCAN-A",
        finding_id="F-1",
    )

    assert stored == {"subtype": "TIME_BASED", "evidence": {}}
