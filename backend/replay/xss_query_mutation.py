from urllib.parse import (
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
)

from backend.models.normalized_finding import (
    NormalizedFinding,
    ParameterLocation,
)
from backend.models.replay_result import ReplayRequest
from backend.replay.request_builder import build_replay_request


def build_reflected_xss_variant_request(
    *,
    finding: NormalizedFinding,
    payload: str,
    session_cookie_override: str | None = None,
) -> ReplayRequest:
    """
    Construct a replay request for one REFLECTED XSS payload variant
    by substituting the finding's tested QUERY parameter value.

    Deliberately limited to QUERY parameters. Normalization
    (backend.parsers.zap / backend.parsers.burp) only ever reliably
    identifies QUERY-string parameters, so this is not an arbitrary
    restriction -- it matches what finding.target actually carries.
    The parameter *name* is never guessed or supplied by the caller:
    it always comes from finding.target.parameter.
    """

    parameter = finding.target.parameter

    if not parameter:
        raise ValueError(
            "REFLECTED XSS verification requires a known tested parameter"
        )

    if finding.target.parameter_location != ParameterLocation.QUERY:
        raise ValueError(
            "REFLECTED XSS query mutation currently supports QUERY "
            "parameters only"
        )

    base_request = build_replay_request(
        finding,
        session_cookie_override=session_cookie_override,
    )

    mutated_url = _replace_single_query_parameter(
        url=base_request.url,
        parameter=parameter,
        replacement_value=payload,
    )

    return ReplayRequest(
        method=base_request.method,
        url=mutated_url,
        headers=dict(base_request.headers),
        body=base_request.body,
    )


def _replace_single_query_parameter(
    *,
    url: str,
    parameter: str,
    replacement_value: str,
) -> str:
    parsed = urlsplit(url)

    pairs = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    matching_indexes = [
        index
        for index, (name, _) in enumerate(pairs)
        if name == parameter
    ]

    if not matching_indexes:
        raise ValueError(
            f"Tested parameter '{parameter}' was not found in the request URL"
        )

    if len(matching_indexes) > 1:
        raise ValueError(
            f"Tested parameter '{parameter}' occurs multiple times in the "
            "request URL; query mutation would be ambiguous"
        )

    index = matching_indexes[0]

    pairs[index] = (
        parameter,
        replacement_value,
    )

    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(pairs, doseq=True),
            parsed.fragment,
        )
    )
