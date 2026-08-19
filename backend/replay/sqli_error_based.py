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


def build_error_based_replay_requests(
    *,
    finding: NormalizedFinding,
) -> tuple[ReplayRequest, ReplayRequest]:
    """
    Construct the two requests required for ERROR_BASED SQLi replay.

    Baseline:
        the exact scanner-captured request, except the tested QUERY
        parameter has the scanner's own captured payload removed
        from its current value (or is cleared entirely, if that
        payload cannot be located in the current value). This is a
        deterministic, data-driven approximation of the
        pre-injection value that requires no caller-supplied input --
        unlike TIME_BASED, ERROR_BASED verification is triggerable
        with an empty configuration, so there is nowhere to obtain an
        explicit clean value from.

    Verification:
        exact scanner-captured request, including the scanner's
        injected value, unmodified.

    Mirrors backend.replay.sqli_time_based.build_time_based_replay_requests
    as closely as possible, including the same QUERY-only restriction
    and the same single-occurrence guard, for the same reason:
    normalization currently only reliably identifies QUERY-string
    parameters.
    """

    if (
        finding.vulnerability.category
        != VulnerabilityCategory.SQLI
    ):
        raise ValueError(
            "ERROR_BASED SQLi request builder received a non-SQLI finding"
        )

    parameter = finding.target.parameter

    if not parameter:
        raise ValueError(
            "ERROR_BASED SQLi verification requires a tested parameter"
        )

    if (
        finding.target.parameter_location
        != ParameterLocation.QUERY
    ):
        raise ValueError(
            "ERROR_BASED SQLi baseline construction currently supports "
            "QUERY parameters only"
        )

    verification_request = build_replay_request(
        finding
    )

    index, current_value = _find_single_query_parameter(
        url=verification_request.url,
        parameter=parameter,
    )

    baseline_value = _derive_baseline_value(
        current_value=current_value,
        payload=finding.original_test.payload,
    )

    baseline_url = _set_query_parameter_at_index(
        url=verification_request.url,
        index=index,
        parameter=parameter,
        replacement_value=baseline_value,
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


def _derive_baseline_value(
    *,
    current_value: str,
    payload: str | None,
) -> str:
    """
    Approximate the pre-injection parameter value without requiring
    the caller to supply one.

    If the scanner's own captured payload is present in the current
    value, removing it is the most precise, data-driven restoration
    available (this is exactly what happens for the reference DVWA
    ZAP finding: current_value=="'" and payload=="'" produce an
    empty baseline value). Otherwise the value is cleared entirely
    rather than guessing a domain-specific "safe" value such as "1".
    """

    if payload and payload in current_value:
        return current_value.replace(
            payload,
            "",
            1,
        )

    return ""


def _find_single_query_parameter(
    *,
    url: str,
    parameter: str,
) -> tuple[int, str]:
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

    return index, pairs[index][1]


def _set_query_parameter_at_index(
    *,
    url: str,
    index: int,
    parameter: str,
    replacement_value: str,
) -> str:
    parsed = urlsplit(url)

    pairs = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

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
