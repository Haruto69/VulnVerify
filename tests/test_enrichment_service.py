import pytest

from backend.models.enrichment import FindingEnrichment
from backend.models.normalized_finding import NormalizedFinding
from backend.services.enrichment_service import enrich_findings


def make_normalized(
    finding_id: str = "f-a",
    scan_id: str = "scan-001",
    scanner: str = "Burp",
    category: str = "SQLI",
    cwe: str | None = "CWE-89",
    references: list[str] | None = None,
    metadata: dict | None = None,
) -> NormalizedFinding:
    return NormalizedFinding(
        scan_id=scan_id,
        finding_id=finding_id,
        source={
            "scanner": scanner,
            "scanner_finding_id": "1",
            "original_name": "SQL Injection",
        },
        vulnerability={
            "category": category,
            "subtype": None,
            "raw_severity": "High",
            "normalized_severity": "HIGH",
            "raw_confidence": "Firm",
            "normalized_confidence": "MEDIUM",
            "cwe": cwe,
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
            "payload": None,
            "evidence": None,
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
        references=references if references is not None else [],
        metadata=metadata if metadata is not None else {},
    )


# ------------------------------------------------------------------
# Description / remediation passthrough
# ------------------------------------------------------------------


def test_burp_description_and_remediation_are_surfaced():
    finding = make_normalized(
        scanner="Burp",
        metadata={
            "burp_issue_background": (
                "<p>An HTML5 CORS policy controls access.</p>"
            ),
            "burp_remediation_background": (
                "<p>Remove inappropriate domains.</p>"
            ),
        },
    )

    result = enrich_findings(findings=[finding])[0]

    assert result.description == (
        "An HTML5 CORS policy controls access."
    )
    assert result.remediation == (
        "Remove inappropriate domains."
    )


def test_zap_description_and_remediation_are_surfaced():
    finding = make_normalized(
        scanner="ZAP",
        metadata={
            "zap_description": (
                "<p>SQL injection may be possible.</p>"
            ),
            "zap_solution": (
                "<p>Do not trust client side input.</p>"
            ),
        },
    )

    result = enrich_findings(findings=[finding])[0]

    assert result.description == (
        "SQL injection may be possible."
    )
    assert result.remediation == (
        "Do not trust client side input."
    )


def test_missing_description_and_remediation_are_none():
    finding = make_normalized(metadata={})

    result = enrich_findings(findings=[finding])[0]

    assert result.description is None
    assert result.remediation is None


# ------------------------------------------------------------------
# OWASP extraction
# ------------------------------------------------------------------


def test_zap_owasp_category_and_url_are_extracted():
    finding = make_normalized(
        scanner="ZAP",
        metadata={
            "zap_tags": [
                {"tag": "POLICY_SEQUENCE", "link": ""},
                {
                    "tag": "OWASP_2021_A03",
                    "link": (
                        "https://owasp.org/Top10/"
                        "A03_2021-Injection/"
                    ),
                },
                {
                    "tag": "OWASP_2017_A01",
                    "link": "https://example.test/other",
                },
            ],
        },
    )

    result = enrich_findings(findings=[finding])[0]

    assert result.owasp_category == "OWASP_2021_A03"
    assert result.owasp_url == (
        "https://owasp.org/Top10/A03_2021-Injection/"
    )


def test_burp_owasp_fields_are_none():
    finding = make_normalized(
        scanner="Burp",
        metadata={
            "burp_issue_background": "<p>Background.</p>",
        },
    )

    result = enrich_findings(findings=[finding])[0]

    assert result.owasp_category is None
    assert result.owasp_url is None


def test_zap_tags_without_owasp_entry_yield_none():
    finding = make_normalized(
        scanner="ZAP",
        metadata={
            "zap_tags": [
                {"tag": "POLICY_QA_STD", "link": ""},
                {"tag": "CWE-565", "link": "https://example.test"},
            ],
        },
    )

    result = enrich_findings(findings=[finding])[0]

    assert result.owasp_category is None
    assert result.owasp_url is None


def test_owasp_tag_with_empty_link_yields_category_without_url():
    finding = make_normalized(
        scanner="ZAP",
        metadata={
            "zap_tags": [
                {"tag": "OWASP_2021_A05", "link": ""},
            ],
        },
    )

    result = enrich_findings(findings=[finding])[0]

    assert result.owasp_category == "OWASP_2021_A05"
    assert result.owasp_url is None


def test_malformed_zap_tags_do_not_raise():
    finding = make_normalized(
        scanner="ZAP",
        metadata={
            "zap_tags": [
                "not-a-dict",
                {"no_tag_key": "x"},
                {"tag": 42},
                None,
            ],
        },
    )

    result = enrich_findings(findings=[finding])[0]

    assert result.owasp_category is None
    assert result.owasp_url is None


def test_zap_tags_not_a_list_does_not_raise():
    finding = make_normalized(
        scanner="ZAP",
        metadata={"zap_tags": "unexpected"},
    )

    result = enrich_findings(findings=[finding])[0]

    assert result.owasp_category is None


# ------------------------------------------------------------------
# CWE URL derivation
# ------------------------------------------------------------------


def test_valid_cwe_produces_mitre_url():
    finding = make_normalized(cwe="CWE-942")

    result = enrich_findings(findings=[finding])[0]

    assert result.cwe == "CWE-942"
    assert result.cwe_url == (
        "https://cwe.mitre.org/data/definitions/942.html"
    )


def test_missing_cwe_produces_no_url():
    finding = make_normalized(cwe=None)

    result = enrich_findings(findings=[finding])[0]

    assert result.cwe is None
    assert result.cwe_url is None


@pytest.mark.parametrize(
    "cwe",
    [
        "CWE-",
        "CWE-abc",
        "-1",
        "0",
        "CWE-0",
        "89",
        "CWE 89",
        "CWE-89-extra",
        "",
        "   ",
    ],
)
def test_malformed_or_sentinel_cwe_produces_no_url(cwe):
    finding = make_normalized(cwe=cwe)

    result = enrich_findings(findings=[finding])[0]

    assert result.cwe_url is None


def test_cwe_value_itself_is_passed_through_unchanged():
    # Even when no URL can be derived, the scanner's own raw value is
    # surfaced rather than blanked out or replaced.
    finding = make_normalized(cwe="-1")

    result = enrich_findings(findings=[finding])[0]

    assert result.cwe == "-1"
    assert result.cwe_url is None


# ------------------------------------------------------------------
# HTML stripping
# ------------------------------------------------------------------


def test_html_is_stripped_from_description_and_remediation():
    finding = make_normalized(
        scanner="Burp",
        metadata={
            "burp_issue_background": (
                "<p>First line.</p><p>Second&nbsp;line "
                "&amp; more.</p>"
            ),
            "burp_remediation_background": (
                "<ul><li>Do    this</li>\n<li>Then that</li></ul>"
            ),
        },
    )

    result = enrich_findings(findings=[finding])[0]

    assert "<" not in result.description
    assert ">" not in result.description
    assert "&amp;" not in result.description
    assert "First line. Second" in result.description

    assert "<" not in result.remediation
    assert "Do this Then that" in result.remediation


def test_html_only_value_becomes_none():
    finding = make_normalized(
        scanner="Burp",
        metadata={"burp_issue_background": "<p></p>"},
    )

    result = enrich_findings(findings=[finding])[0]

    assert result.description is None


# ------------------------------------------------------------------
# References / general behaviour
# ------------------------------------------------------------------


def test_references_are_passed_through_unchanged():
    references = [
        "https://portswigger.net/web-security/cors",
        "https://cwe.mitre.org/data/definitions/942.html",
    ]

    finding = make_normalized(references=references)

    result = enrich_findings(findings=[finding])[0]

    assert result.references == references


def test_empty_references_are_preserved_as_empty_list():
    finding = make_normalized(references=[])

    result = enrich_findings(findings=[finding])[0]

    assert result.references == []


def test_scanner_and_identity_fields_are_preserved():
    finding = make_normalized(
        finding_id="f-xyz",
        scan_id="scan-xyz",
        scanner="ZAP",
    )

    result = enrich_findings(findings=[finding])[0]

    assert result.finding_id == "f-xyz"
    assert result.scan_id == "scan-xyz"
    assert result.scanner == "ZAP"


def test_empty_input_produces_no_enrichments():
    assert enrich_findings(findings=[]) == []


def test_multiple_findings_produce_one_enrichment_each():
    findings = [
        make_normalized(finding_id="f-a"),
        make_normalized(finding_id="f-b"),
        make_normalized(finding_id="f-c"),
    ]

    results = enrich_findings(findings=findings)

    assert [r.finding_id for r in results] == [
        "f-a",
        "f-b",
        "f-c",
    ]


def test_inputs_are_not_mutated():
    finding = make_normalized(
        scanner="Burp",
        references=["https://example.test/ref"],
        metadata={
            "burp_issue_background": "<p>Background.</p>",
            "burp_remediation_background": "<p>Fix it.</p>",
        },
    )

    before = finding.model_copy(deep=True)

    enrich_findings(findings=[finding])

    assert finding == before


def test_mutating_enrichment_references_does_not_affect_finding():
    finding = make_normalized(
        references=["https://example.test/ref"],
    )

    result = enrich_findings(findings=[finding])[0]

    result.references.append("https://example.test/injected")

    assert finding.references == ["https://example.test/ref"]


# ------------------------------------------------------------------
# Regression guard: enrichment is context, not a scoring system
# ------------------------------------------------------------------


def test_enrichment_model_exposes_no_scoring_fields():
    forbidden = {
        "severity",
        "normalized_severity",
        "scanner_severity",
        "confidence",
        "verification_confidence",
        "priority",
        "priority_level",
        "cvss",
        "cvss_score",
        "cvss_vector",
        "cve",
        "exploitability",
        "business_impact",
        "risk_score",
        "verification_status",
    }

    actual = set(FindingEnrichment.model_fields)

    assert actual & forbidden == set()
