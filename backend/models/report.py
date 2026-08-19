from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from backend.models.evaluation import EvaluationMetrics


class ReportFinding(BaseModel):
    """
    One row of the report -- a normalized finding joined with
    whatever verification/priority data already exists for it.

    verification_status/verification_reason/priority/priority_reason
    are all None when the finding hasn't been verified yet; the
    report never fabricates a status for an unverified finding.
    """

    finding_id: str
    original_name: str
    category: str
    scanner_severity: str
    normalized_url: str
    parameter: str | None
    cwe: str | None

    verification_status: str | None = None
    verification_reason: str | None = None

    priority: str | None = None
    priority_reason: str | None = None


class ScanReport(BaseModel):
    """
    A point-in-time report for one scan, assembled entirely from
    data already produced by the existing pipeline (normalization,
    verification, risk assessment, deduplication, evaluation) --
    nothing here is computed or scored independently of those
    services.
    """

    schema_version: Literal["1.0"] = "1.0"

    scan_id: str
    filename: str
    scanner: str
    generated_at: datetime

    raw_finding_count: int
    verified_count: int
    true_positive_count: int
    false_positive_count: int
    inconclusive_count: int
    unverified_count: int
    unique_vulnerability_count: int

    findings: list[ReportFinding]
    evaluation: EvaluationMetrics
