from urllib.parse import (
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
)

from backend.models.normalized_finding import (
    NormalizedFinding,
    ParameterLocation,
    VulnerabilityCategory,
)
from backend.models.replay_result import ReplayRequest
from backend.replay.request_builder import (
    build_replay_request,
)


def build_time_based_replay_requests(
    *,
    finding: NormalizedFinding,
    baseline_parameter_value: str,
) -> tuple[ReplayRequest, ReplayRequest]:
    """
    Construct the two requests required by the frozen TIME_BASED
    SQLi replay contract.

    Baseline:
        exact scanner request except the tested QUERY parameter is
        restored to the explicitly supplied pre-injection value.

    Verification:
        exact scanner-captured request, including the scanner's
        injected value.

    Current deterministic support is intentionally limited to QUERY
    parameters because that is the parameter location currently
    produced by the ZAP SQLi parser. Other locations must gain their
    own frozen mutation rules before being implemented.
    """

    if (
        finding.vulnerability.category
        != VulnerabilityCategory.SQLI
    ):
        raise ValueError(
            "TIME_BASED SQLi request builder received a non-SQLI finding"
        )

    parameter = finding.target.parameter

    if not parameter:
        raise ValueError(
            "TIME_BASED SQLi verification requires a tested parameter"
        )

    if (
        finding.target.parameter_location
        != ParameterLocation.QUERY
    ):
        raise ValueError(
            "TIME_BASED SQLi baseline construction currently supports "
            "QUERY parameters only"
        )

    verification_request = build_replay_request(
        finding
    )

    baseline_url = _replace_single_query_parameter(
        url=verification_request.url,
        parameter=parameter,
        replacement_value=baseline_parameter_value,
    )

    baseline_request = ReplayRequest(
        method=verification_request.method,
        url=baseline_url,
        headers=dict(verification_request.headers),
        body=verification_request.body,
    )

    return (
        baseline_request,
        verification_request,
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
            "request URL; baseline mutation would be ambiguous"
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