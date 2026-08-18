import html
import re

from backend.models.enrichment import FindingEnrichment
from backend.models.normalized_finding import NormalizedFinding


_CWE_PATTERN = re.compile(
    r"^CWE-(\d+)$",
    re.IGNORECASE,
)

_CWE_URL_TEMPLATE = (
    "https://cwe.mitre.org/data/definitions/{digits}.html"
)

# ZAP reports these as "no CWE assigned" rather than as real CWE ids.
_CWE_SENTINELS = {"-1", "0"}

_TAG_PATTERN = re.compile(r"<[^>]+>")
_WHITESPACE_PATTERN = re.compile(r"\s+")


def enrich_findings(
    *,
    findings: list[NormalizedFinding],
) -> list[FindingEnrichment]:
    """
    Produce supplementary context for each normalized finding.

    Pure function: no I/O, no repository access, no network calls, no
    persistence. Inputs are read only, never mutated.

    Deliberately takes NormalizedFinding alone rather than
    (NormalizedFinding, VerifiedFinding) pairs -- unlike the
    deduplication and risk services -- because every enrichment field
    originates in the normalized finding. Requiring verification would
    create a false data dependency and would return nothing for a
    freshly uploaded scan.

    Never invents a description, remediation, CWE, OWASP category, or
    reference: a value the scanner did not supply stays None.
    """

    return [
        _enrich_one(finding)
        for finding in findings
    ]


def _enrich_one(
    finding: NormalizedFinding,
) -> FindingEnrichment:
    metadata = finding.metadata or {}

    cwe = finding.vulnerability.cwe

    owasp_category, owasp_url = _extract_owasp(metadata)

    return FindingEnrichment(
        scan_id=finding.scan_id,
        finding_id=finding.finding_id,
        scanner=finding.source.scanner,
        cwe=cwe,
        cwe_url=_build_cwe_url(cwe),
        owasp_category=owasp_category,
        owasp_url=owasp_url,
        description=_strip_html(
            _first_present(
                metadata,
                "burp_issue_background",
                "zap_description",
            )
        ),
        remediation=_strip_html(
            _first_present(
                metadata,
                "burp_remediation_background",
                "zap_solution",
            )
        ),
        references=list(finding.references),
    )


def _first_present(
    metadata: dict,
    *keys: str,
) -> str | None:
    """
    Return the first non-empty string value among `keys`.

    Scanner-specific keys are looked up by name rather than branching
    on finding.source.scanner, so a finding carrying neither key
    simply yields None instead of raising.
    """

    for key in keys:
        value = metadata.get(key)

        if isinstance(value, str) and value.strip():
            return value

    return None


def _extract_owasp(
    metadata: dict,
) -> tuple[str | None, str | None]:
    """
    Extract the first OWASP_* entry from ZAP's tag list.

    Burp reports carry no OWASP mapping at all, so Burp findings
    always yield (None, None) here.
    """

    tags = metadata.get("zap_tags")

    if not isinstance(tags, list):
        return (None, None)

    for tag in tags:
        if not isinstance(tag, dict):
            continue

        name = tag.get("tag")

        if not isinstance(name, str):
            continue

        if not name.startswith("OWASP_"):
            continue

        link = tag.get("link")

        if not isinstance(link, str) or not link.strip():
            link = None

        return (name, link)

    return (None, None)


def _build_cwe_url(
    cwe: str | None,
) -> str | None:
    """
    Build the MITRE definition URL for a valid CWE-<digits> value.

    Missing values, ZAP's -1/0 sentinels, and any malformed value
    yield None rather than a fabricated URL.
    """

    if not isinstance(cwe, str):
        return None

    candidate = cwe.strip()

    if candidate in _CWE_SENTINELS:
        return None

    match = _CWE_PATTERN.match(candidate)

    if match is None:
        return None

    digits = match.group(1)

    if digits.lstrip("0") == "" or digits in _CWE_SENTINELS:
        return None

    return _CWE_URL_TEMPLATE.format(digits=digits)


def _strip_html(
    value: str | None,
) -> str | None:
    """
    Reduce scanner-supplied HTML prose to plain text.

    Mirrors the existing cleaning behaviour in
    backend.parsers.burp.BurpParser._clean_html (that method is
    instance-private to the parser, so the small amount of logic is
    repeated here rather than reaching into the parser).
    """

    if not value:
        return None

    unescaped = html.unescape(value)

    without_tags = _TAG_PATTERN.sub(" ", unescaped)

    collapsed = _WHITESPACE_PATTERN.sub(" ", without_tags)

    return collapsed.strip() or None
