from typing import Literal

from pydantic import BaseModel, Field


class FindingEnrichment(BaseModel):
    """
    Supplementary context for one normalized finding.

    Every field is either copied verbatim from data the scanner
    already supplied (via the parsers) or left None. Nothing here is
    inferred, defaulted, or synthesised: there is deliberately no
    severity, confidence, priority, exploitability, business-impact,
    CVSS, or CVE field. Enrichment is context, not a second scoring
    system.

    cwe_url is the single mechanical derivation, built from a valid
    CWE-<digits> value only. Both scanners already emit the same
    MITRE URL in their own reference/tag data.
    """

    schema_version: Literal["1.0"] = "1.0"

    scan_id: str
    finding_id: str

    scanner: str

    cwe: str | None = None
    cwe_url: str | None = None

    owasp_category: str | None = None
    owasp_url: str | None = None

    description: str | None = None
    remediation: str | None = None

    references: list[str] = Field(
        default_factory=list
    )
