"""
HAR (HTTP Archive) parsing for ZAP's traffic-export path.

This is a distinct path from backend/parsers/zap.py's Traditional
JSON alert parsing -- a HAR file carries raw captured traffic with no
scanner risk/vulnerability judgment at all, so it cannot be treated
like an alert. Only entries the structural CSRF candidate detector
(backend/verification/csrf_candidate_detection.py) actually flags
become findings; every other HAR entry is discarded. This module
never converts arbitrary traffic into a finding on its own.
"""

from urllib.parse import parse_qs, urlsplit, urlunsplit
from uuid import uuid4

from backend.models.normalized_finding import (
    FindingContext,
    FindingSource,
    HttpRequest,
    HttpResponse,
    NormalizedFinding,
    NormalizedConfidence,
    NormalizedSeverity,
    OriginalTest,
    ParameterLocation,
    RequirementState,
    TargetInfo,
    VulnerabilityInfo,
)
from backend.verification.csrf_candidate_detection import (
    CsrfCandidate,
    find_csrf_candidates,
)

# A finding produced by this path carries this exact marker in its
# metadata -- backend/api/findings.py reads it to mark the resulting
# CSRF verification context as scanner_related_signal_only, since
# this evidence is structurally weaker than a scanner-emitted alert.
CSRF_CANDIDATE_SOURCE = "har_form_analysis"


def is_har_report(report: dict) -> bool:
    """
    True only for a report that actually has the HAR shape
    (log.entries[]). Never guesses from file extension or any other
    signal -- callers (backend/parsers/zap.py) must not silently
    treat arbitrary JSON as HAR.
    """

    log = report.get("log")
    return isinstance(log, dict) and isinstance(
        log.get("entries"), list
    )


def parse_har_report(
    report: dict,
    scan_id: str,
) -> list[NormalizedFinding]:
    """
    Parse a HAR report into NormalizedFindings.

    Only CSRF candidates identified by the structural detector become
    findings -- this function never creates one finding per HAR
    entry.
    """

    entries = _validate_har_structure(report)

    candidates = find_csrf_candidates(entries)

    return [
        _build_finding_from_candidate(
            candidate=candidate,
            entries=entries,
            scan_id=scan_id,
        )
        for candidate in candidates
    ]


def _validate_har_structure(report: dict) -> list[dict]:
    log = report.get("log")

    if not isinstance(log, dict):
        raise ValueError(
            "Invalid HAR report: missing 'log' object"
        )

    entries = log.get("entries")

    if not isinstance(entries, list):
        raise ValueError(
            "Invalid HAR report: missing 'log.entries' list"
        )

    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(
            entry.get("request"), dict
        ):
            raise ValueError(
                "Invalid HAR report: entry is missing a "
                "'request' object"
            )

    return entries


def _build_finding_from_candidate(
    candidate: CsrfCandidate,
    entries: list[dict],
    scan_id: str,
) -> NormalizedFinding:
    entry = entries[candidate.request_entry_index]

    request = entry.get("request") or {}
    response = entry.get("response") or {}

    url = str(request.get("url", ""))
    parsed_url = urlsplit(url)

    normalized_url = urlunsplit(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path or "/", "", "")
    )

    query_parameters = _extract_query_parameters(request)
    request_headers = _extract_header_map(request.get("headers"))
    request_cookies = _extract_cookie_map(request.get("cookies"))
    response_headers = _extract_header_map(response.get("headers"))
    response_cookies = _extract_cookie_map(response.get("cookies"))

    body = _extract_post_body(request)

    status_code = response.get("status")

    if not isinstance(status_code, int):
        status_code = 0

    return NormalizedFinding(
        scan_id=scan_id,
        finding_id=str(uuid4()),

        source=FindingSource(
            scanner="ZAP",
            scanner_finding_id=None,
            original_name="Cross-Site Request Forgery (candidate)",
        ),

        vulnerability=VulnerabilityInfo(
            category="CSRF",
            subtype=None,

            raw_severity="Unknown",
            normalized_severity=NormalizedSeverity.UNKNOWN,

            raw_confidence=None,
            normalized_confidence=NormalizedConfidence.UNKNOWN,

            # CWE-352 is the standard, well-known CWE identifier for
            # the CSRF category itself -- not an inferred fact about
            # this specific request, the same way ZapParser's own
            # alert-based path already assigns a fixed category CWE.
            cwe="CWE-352",
        ),

        target=TargetInfo(
            url=url,
            normalized_url=normalized_url,
            host=parsed_url.hostname or "",
            path=parsed_url.path or "/",
            parameter=None,
            parameter_location=ParameterLocation.UNKNOWN,
        ),

        original_test=OriginalTest(
            payload=None,
            evidence=(
                "Form at "
                f"{candidate.form.source_url} declares no "
                "recognized anti-CSRF token field; a later captured "
                "request submits matching fields: "
                f"{', '.join(candidate.matched_field_names) or '(none)'}."
            ),
        ),

        request=HttpRequest(
            method=str(request.get("method", "GET")),
            url=url,
            path=parsed_url.path or "/",
            query_parameters=query_parameters,
            headers=request_headers,
            cookies=request_cookies,
            body=body,
            content_type=request_headers.get("content-type"),
            raw=None,
        ),

        response=HttpResponse(
            status_code=status_code,
            headers=response_headers,
            cookies=response_cookies,
            # The captured response body is deliberately not stored:
            # it is not used anywhere in CSRF verification (which
            # relies on its own fresh replay, not this snapshot) and
            # may contain sensitive account details for a real
            # password-change-style response.
            body=None,
            raw=None,
            response_time_ms=None,
        ),

        context=FindingContext(
            authentication_required=RequirementState.UNKNOWN,
            session_required=RequirementState.UNKNOWN,
        ),

        references=[],

        metadata={
            "csrf_candidate_source": CSRF_CANDIDATE_SOURCE,
            "matched_form_action": candidate.form.action_url,
            "matched_field_names": list(
                candidate.matched_field_names
            ),
        },
    )


def _extract_query_parameters(
    request: dict,
) -> dict[str, list[str]]:
    query_string = request.get("queryString")
    params: dict[str, list[str]] = {}

    if isinstance(query_string, list):
        for item in query_string:
            if not isinstance(item, dict):
                continue

            name = item.get("name")
            value = item.get("value", "")

            if not isinstance(name, str):
                continue

            params.setdefault(name, []).append(
                value if isinstance(value, str) else ""
            )

        return params

    query = urlsplit(request.get("url", "")).query
    return parse_qs(query, keep_blank_values=True)


def _extract_post_body(request: dict) -> str | None:
    post_data = request.get("postData")

    if not isinstance(post_data, dict):
        return None

    text = post_data.get("text")

    return text if isinstance(text, str) and text else None


def _extract_header_map(
    items: object,
) -> dict[str, str]:
    headers: dict[str, str] = {}

    if not isinstance(items, list):
        return headers

    for item in items:
        if not isinstance(item, dict):
            continue

        name = item.get("name")
        value = item.get("value")

        if isinstance(name, str) and isinstance(value, str):
            headers[name.strip().lower()] = value

    return headers


def _extract_cookie_map(
    items: object,
) -> dict[str, str]:
    cookies: dict[str, str] = {}

    if not isinstance(items, list):
        return cookies

    for item in items:
        if not isinstance(item, dict):
            continue

        name = item.get("name")
        value = item.get("value")

        if isinstance(name, str) and isinstance(value, str):
            cookies[name] = value

    return cookies
