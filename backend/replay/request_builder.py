from backend.models.normalized_finding import NormalizedFinding
from backend.models.replay_result import ReplayRequest


def build_replay_request(
    finding: NormalizedFinding,
    session_cookie_override: str | None = None,
) -> ReplayRequest:
    """
    Build a replay-ready request from a normalized finding.

    This function only reconstructs the request captured during
    normalization. It does not perform vulnerability-specific
    mutations or send the request.

    session_cookie_override, when supplied, replaces only the Cookie
    header with a freshly-obtained session (see
    backend/replay/session_refresh.py) -- method, URL, query
    parameters, body, and every other header are still taken exactly
    from the scanner capture, unchanged. Callers that don't pass it
    (the default) get byte-for-byte the same request this function
    always built.
    """

    headers = dict(finding.request.headers)

    if session_cookie_override is not None:
        # Header names captured from scanner reports are already
        # lowercased (see backend/parsers/zap.py::_parse_headers and
        # backend/parsers/zap_har.py::_extract_header_map), so this
        # both replaces an existing scanner-captured Cookie header and
        # adds one if none was captured at all -- covers a finding
        # whose original request had no session cookie yet still
        # requires one for a fresh authenticated replay.
        headers["cookie"] = session_cookie_override

    return ReplayRequest(
        method=finding.request.method,
        url=finding.request.url,
        headers=headers,
        body=finding.request.body,
    )