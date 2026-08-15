import pytest
from pydantic import ValidationError

from backend.models.verified_finding import VerifiedFinding


def test_valid_verified_finding():
    finding = VerifiedFinding(
        finding_id="finding-001",
        classification={
            "status": "TRUE_POSITIVE",
            "confidence": 0.96,
            "reason": (
                "Controlled replay reproduced "
                "the expected behavior."
            ),
        },
        evidence={
            "indicators": [
                "payload_reflected"
            ],
            "request_reference": "REQ-001",
            "response_reference": "RES-001",
        },
        verification_method=(
            "xss_reflection_rule_v1"
        ),
    )

    assert finding.schema_version == "1.0"
    assert finding.finding_id == "finding-001"

    assert (
        finding.classification.status
        == "TRUE_POSITIVE"
    )

    assert (
        finding.classification.confidence
        == 0.96
    )

    assert (
        finding.evidence.indicators
        == ["payload_reflected"]
    )

    assert (
        finding.verification_method
        == "xss_reflection_rule_v1"
    )


def test_inconclusive_verified_finding():
    finding = VerifiedFinding(
        finding_id="finding-002",
        classification={
            "status": "INCONCLUSIVE",
            "confidence": 0.40,
            "reason": (
                "Replay could not be completed "
                "because the target was unreachable."
            ),
        },
        evidence={
            "indicators": [],
            "request_reference": "REQ-002",
            "response_reference": None,
        },
        verification_method=(
            "generic_replay_rule_v1"
        ),
    )

    assert (
        finding.classification.status
        == "INCONCLUSIVE"
    )

    assert (
        finding.evidence.response_reference
        is None
    )


def test_invalid_verification_status():
    with pytest.raises(ValidationError):
        VerifiedFinding(
            finding_id="finding-003",
            classification={
                "status": "MAYBE",
                "confidence": 0.50,
                "reason": "Invalid status.",
            },
            evidence={
                "indicators": [],
            },
            verification_method="test_rule_v1",
        )