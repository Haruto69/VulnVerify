"""
Proves the SQLite-backed persistence layer (backend/storage/db.py,
backend/storage/collections.py) actually survives a backend restart,
not just "the same process can read back what it just wrote" (which
the old in-memory dicts could already do).

Two levels of proof:

  - test_fresh_store_instances_see_data_written_by_other_instances:
    constructs brand-new ScanStore/NormalizedFindingsStore/
    VerifiedFindingsStore/GroundTruthStore instances pointed at the
    same database file and confirms they see data written through the
    module-level repository objects -- proving the storage classes
    hold no process-local cache of their own.

  - test_data_survives_a_real_separate_process: writes data in this
    test process, then launches a completely separate `python -c ...`
    subprocess (a real OS process, its own fresh Python interpreter,
    no shared memory) pointed at the exact same database file via
    VULNVERIFY_DB_PATH, and has it read the data back and report
    success -- this is the actual "stop the backend, start it again"
    scenario, not a simulation of it.

  - test_endpoints_return_data_after_reinitializing_storage: exercises
    the real HTTP surface (upload, verify, ground truth, findings,
    verified-findings, report, metrics, scan history) through
    TestClient, then rebinds backend.storage.repository's module-level
    objects to freshly-constructed Store instances (as close to
    "restart the process" as is possible without literally doing so
    inside a single pytest run) and re-issues the same GET requests.
"""

import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

import backend.storage.repository as repository
from backend.main import app
from backend.models.ground_truth import GroundTruthLabel
from backend.models.normalized_finding import (
    FindingSource,
    HttpRequest,
    NormalizedConfidence,
    NormalizedFinding,
    NormalizedSeverity,
    OriginalTest,
    ParameterLocation,
    TargetInfo,
    VulnerabilityCategory,
    VulnerabilityInfo,
)
from backend.models.verified_finding import VerifiedFinding
from backend.services.ground_truth_service import (
    save_ground_truth_labels,
)
from backend.storage.collections import (
    GroundTruthStore,
    NormalizedFindingsStore,
    ScanStore,
    VerifiedFindingsStore,
)
from backend.storage.db import get_db_path


REPO_ROOT = Path(__file__).resolve().parent.parent


def make_finding(
    scan_id: str,
    finding_id: str,
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id=scan_id,
        finding_id=finding_id,
        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id="40018",
            original_name="SQL Injection",
        ),
        vulnerability=VulnerabilityInfo(
            category=VulnerabilityCategory.SQLI,
            subtype=None,
            raw_severity="High",
            normalized_severity=NormalizedSeverity.HIGH,
            raw_confidence="Medium",
            normalized_confidence=NormalizedConfidence.MEDIUM,
            cwe="CWE-89",
        ),
        target=TargetInfo(
            url="http://127.0.0.1/DVWA/vulnerabilities/sqli/?id=1",
            normalized_url=(
                "http://127.0.0.1/DVWA/vulnerabilities/sqli/"
            ),
            host="127.0.0.1",
            path="/DVWA/vulnerabilities/sqli/",
            parameter="id",
            parameter_location=ParameterLocation.QUERY,
        ),
        original_test=OriginalTest(
            payload="'", evidence="SQL syntax error"
        ),
        request=HttpRequest(
            method="GET",
            url="http://127.0.0.1/DVWA/vulnerabilities/sqli/?id=1",
            path="/DVWA/vulnerabilities/sqli/",
        ),
    )


def make_verified(finding_id: str) -> VerifiedFinding:
    return VerifiedFinding(
        finding_id=finding_id,
        classification={
            "status": "TRUE_POSITIVE",
            "confidence": 0.9,
            "reason": "persistence test",
        },
        evidence={
            "indicators": ["stable_timing_baseline"],
            "request_reference": f"{finding_id}:request",
            "response_reference": f"{finding_id}:response",
        },
        verification_method="sqli_error_based_rule_v1",
    )


# ---------------------------------------------------------------------
# 1. Save scan / findings / verified finding / ground truth, then read
# them back through brand-new Store instances (not the module-level
# singletons that wrote them) pointed at the same file.
# ---------------------------------------------------------------------


def test_fresh_store_instances_see_data_written_by_other_instances():
    scan_id = "scan-persist-001"
    finding_id = "sqli-persist-001"

    repository.scans.clear()
    repository.normalized_findings.clear()
    repository.verified_findings.clear()
    repository.ground_truth.clear()

    repository.scans[scan_id] = {
        "scan_id": scan_id,
        "filename": "zap_sqli_positive.json",
        "content_type": "application/json",
        "scanner": "ZAP",
        "status": "NORMALIZED",
        "error": None,
    }

    finding = make_finding(scan_id, finding_id)
    repository.normalized_findings[scan_id] = [finding]

    verified = make_verified(finding_id)
    repository.verified_findings[scan_id] = {
        finding_id: verified
    }

    label = GroundTruthLabel(
        finding_id=finding_id,
        expected_status="TRUE_POSITIVE",
        note="known-good SQLi",
    )
    repository.ground_truth[scan_id] = {finding_id: label}

    # Fresh instances -- not repository.scans etc. -- backed by the
    # exact same database file.
    fresh_scans = ScanStore()
    fresh_normalized = NormalizedFindingsStore()
    fresh_verified = VerifiedFindingsStore()
    fresh_ground_truth = GroundTruthStore()

    assert fresh_scans[scan_id]["scan_id"] == scan_id
    assert fresh_scans[scan_id]["filename"] == "zap_sqli_positive.json"
    assert fresh_scans[scan_id]["status"] == "NORMALIZED"

    reloaded_findings = fresh_normalized[scan_id]
    assert len(reloaded_findings) == 1
    assert reloaded_findings[0].finding_id == finding_id
    assert reloaded_findings[0].vulnerability.category == "SQLI"
    assert reloaded_findings[0].target.parameter == "id"

    reloaded_verified = fresh_verified[scan_id]
    assert finding_id in reloaded_verified
    assert (
        reloaded_verified[finding_id].classification.status
        == "TRUE_POSITIVE"
    )

    reloaded_labels = fresh_ground_truth[scan_id]
    assert finding_id in reloaded_labels
    assert (
        reloaded_labels[finding_id].expected_status
        == "TRUE_POSITIVE"
    )
    assert reloaded_labels[finding_id].note == "known-good SQLi"


# ---------------------------------------------------------------------
# 2. The real "stop the backend, start it again" scenario: a
# completely separate OS process reads back what this process wrote.
# ---------------------------------------------------------------------


def test_data_survives_a_real_separate_process():
    scan_id = "scan-persist-subprocess-001"
    finding_id = "sqli-persist-subprocess-001"

    repository.scans.clear()
    repository.normalized_findings.clear()
    repository.verified_findings.clear()

    repository.scans[scan_id] = {
        "scan_id": scan_id,
        "filename": "restart-proof.json",
        "content_type": "application/json",
        "scanner": "ZAP",
        "status": "NORMALIZED",
        "error": None,
    }
    repository.normalized_findings[scan_id] = [
        make_finding(scan_id, finding_id)
    ]
    repository.verified_findings[scan_id] = {
        finding_id: make_verified(finding_id)
    }

    db_path = str(get_db_path())

    script = f"""
import sys
sys.path.insert(0, {str(REPO_ROOT)!r})
import os
os.environ["VULNVERIFY_DB_PATH"] = {db_path!r}

from backend.services.scan_service import (
    get_scan,
    get_normalized_findings,
    get_verified_findings,
)

scan = get_scan({scan_id!r})
assert scan is not None, "scan not found in a fresh process"
assert scan["filename"] == "restart-proof.json"
assert scan["status"] == "NORMALIZED"

findings = get_normalized_findings({scan_id!r})
assert len(findings) == 1
assert findings[0].finding_id == {finding_id!r}

verified = get_verified_findings({scan_id!r})
assert len(verified) == 1
assert verified[0].classification.status == "TRUE_POSITIVE"

print("SUBPROCESS_PERSISTENCE_OK")
"""

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, (
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "SUBPROCESS_PERSISTENCE_OK" in result.stdout


# ---------------------------------------------------------------------
# 3. Real HTTP endpoints (upload, verify, ground truth, findings,
# verified-findings, report, metrics, scan history) return the same
# data after backend.storage.repository's module-level Store objects
# are rebound to freshly-constructed instances -- the closest a single
# pytest process can get to "restart the backend" without literally
# spawning a new one, on top of the literal subprocess proof above.
# ---------------------------------------------------------------------


def test_endpoints_return_data_after_reinitializing_storage(
    monkeypatch,
):
    client = TestClient(app)

    repository.scans.clear()
    repository.normalized_findings.clear()
    repository.verified_findings.clear()
    repository.ground_truth.clear()

    with open(
        "tests/fixtures/zap/zap_sqli_positive.json", "rb"
    ) as f:
        upload_response = client.post(
            "/api/v1/scans",
            data={"scanner": "ZAP"},
            files={
                "file": (
                    "zap_sqli_positive.json",
                    f,
                    "application/json",
                )
            },
        )

    assert upload_response.status_code == 200
    scan_id = upload_response.json()["scan_id"]

    findings_response = client.get(
        f"/api/v1/scans/{scan_id}/findings"
    )
    finding_id = findings_response.json()["findings"][0][
        "finding_id"
    ]

    # Manually record a verified result and a ground-truth label
    # directly through the persistence layer (equivalent to what
    # /verify and /ground-truth would store) -- this test is about
    # proving storage survives reinitialization, not re-exercising
    # replay/classification logic already covered elsewhere.
    from backend.services.scan_service import save_verified_finding

    save_verified_finding(
        scan_id=scan_id,
        finding=make_verified(finding_id),
    )

    save_ground_truth_labels(
        scan_id,
        [
            GroundTruthLabel(
                finding_id=finding_id,
                expected_status="TRUE_POSITIVE",
                note="restart proof",
            )
        ],
    )

    # Simulate reinitializing storage the way a fresh backend process
    # would: rebind the module-level objects to brand-new instances
    # backed by the same database file.
    monkeypatch.setattr(
        repository, "scans", ScanStore()
    )
    monkeypatch.setattr(
        repository,
        "normalized_findings",
        NormalizedFindingsStore(),
    )
    monkeypatch.setattr(
        repository,
        "verified_findings",
        VerifiedFindingsStore(),
    )
    monkeypatch.setattr(
        repository, "ground_truth", GroundTruthStore()
    )

    # GET /scans still returns the scan.
    scans_response = client.get("/api/v1/scans")
    assert scans_response.status_code == 200
    assert any(
        scan["scan_id"] == scan_id
        for scan in scans_response.json()
    )

    # The findings still exist.
    findings_after = client.get(
        f"/api/v1/scans/{scan_id}/findings"
    )
    assert findings_after.status_code == 200
    assert findings_after.json()["count"] == 1

    # Verified findings still exist.
    verified_after = client.get(
        f"/api/v1/scans/{scan_id}/verified-findings"
    )
    assert verified_after.status_code == 200
    assert verified_after.json()["count"] == 1
    assert (
        verified_after.json()["findings"][0]["classification"][
            "status"
        ]
        == "TRUE_POSITIVE"
    )

    # Scan History works (status endpoint, same as loadScan's
    # underlying data source).
    status_after = client.get(f"/api/v1/scans/{scan_id}/status")
    assert status_after.status_code == 200
    assert status_after.json()["status"] == "NORMALIZED"

    # Ground truth still exists.
    ground_truth_after = client.get(
        f"/api/v1/scans/{scan_id}/ground-truth"
    )
    assert ground_truth_after.status_code == 200
    assert ground_truth_after.json()["count"] == 1

    # Reports still work.
    report_after = client.get(f"/api/v1/scans/{scan_id}/report")
    assert report_after.status_code == 200

    # Metrics still work where their required data exists (ground
    # truth was just re-saved above, so this scan does have it).
    metrics_after = client.get(f"/api/v1/scans/{scan_id}/metrics")
    assert metrics_after.status_code == 200
