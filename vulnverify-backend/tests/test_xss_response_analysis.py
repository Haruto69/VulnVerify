from backend.models.replay_result import ReplayResponse
from backend.verification.xss_response_analysis import (
    XssResponseBucket,
    analyze_reflected_xss_response,
    _csp_permits_inline_script,
)


def make_response(
    body: str | None,
    headers: dict[str, str] | None = None,
) -> ReplayResponse:
    return ReplayResponse(
        status=200,
        headers=headers or {},
        body=body,
    )


PAYLOAD = "XSSMARK3R"


def test_payload_absent():
    response = make_response("<html><body>hello</body></html>")

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=response,
    )

    assert result.bucket == XssResponseBucket.ABSENT
    assert result.payload_absent is True
    assert result.payload_reflected_or_rendered is False


def test_payload_absent_when_body_is_none():
    response = make_response(None)

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=response,
    )

    assert result.bucket == XssResponseBucket.ABSENT
    assert result.payload_absent is True


def test_payload_html_entity_escaped():
    body = f"<div>&lt;script&gt;{PAYLOAD}&lt;/script&gt;</div>"

    result = analyze_reflected_xss_response(
        payload=f"<script>{PAYLOAD}</script>",
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.ENCODED_OR_SANITIZED
    assert result.payload_encoded_or_sanitized is True
    assert result.payload_reflected_or_rendered is False


def test_payload_numeric_entity_escaped():
    payload = "<x>"
    body = "<div>&#60;x&#62;</div>"

    result = analyze_reflected_xss_response(
        payload=payload,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.ENCODED_OR_SANITIZED
    assert result.payload_encoded_or_sanitized is True


def test_inert_html_comment():
    body = f"<html><!-- {PAYLOAD} --></html>"

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.INERT_CONTEXT
    assert result.payload_only_in_non_executable_context is True
    assert result.payload_reflected_or_rendered is True
    assert result.payload_unescaped_in_executable_context is False


def test_inert_textarea_rcdata():
    body = f"<textarea>{PAYLOAD}</textarea>"

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.INERT_CONTEXT
    assert result.payload_only_in_non_executable_context is True


def test_inert_title_rcdata():
    body = f"<title>{PAYLOAD}</title>"

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.INERT_CONTEXT
    assert result.payload_only_in_non_executable_context is True


def test_inert_plain_attribute_value():
    body = f'<div data-note="{PAYLOAD}">hi</div>'

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.INERT_CONTEXT
    assert result.payload_only_in_non_executable_context is True


def test_executable_new_script_element():
    payload = f"<script>{PAYLOAD}</script>"
    body = f"<div>{payload}</div>"

    result = analyze_reflected_xss_response(
        payload=payload,
        response=make_response(body, headers={}),
    )

    assert result.bucket == XssResponseBucket.EXECUTABLE_CONTEXT
    assert result.payload_unescaped_in_executable_context is True
    assert result.payload_reflected_or_rendered is True
    assert result.no_interfering_csp_encoding_or_sanitization is True


def test_executable_event_handler_attribute():
    body = f'<img src="x" onerror="{PAYLOAD}">'

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.EXECUTABLE_CONTEXT
    assert result.payload_unescaped_in_executable_context is True


def test_executable_context_blocked_by_restrictive_csp():
    payload = f"<script>{PAYLOAD}</script>"
    body = f"<div>{payload}</div>"

    result = analyze_reflected_xss_response(
        payload=payload,
        response=make_response(
            body,
            headers={
                "Content-Security-Policy": "script-src 'self'",
            },
        ),
    )

    assert result.bucket == XssResponseBucket.EXECUTABLE_CONTEXT
    assert result.no_interfering_csp_encoding_or_sanitization is False


def test_executable_context_permitted_by_unsafe_inline_csp():
    payload = f"<script>{PAYLOAD}</script>"
    body = f"<div>{payload}</div>"

    result = analyze_reflected_xss_response(
        payload=payload,
        response=make_response(
            body,
            headers={
                "Content-Security-Policy": (
                    "script-src 'self' 'unsafe-inline'"
                ),
            },
        ),
    )

    assert result.no_interfering_csp_encoding_or_sanitization is True


def test_ambiguous_plain_text_node():
    body = f"<p>{PAYLOAD}</p>"

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.AMBIGUOUS
    assert result.payload_absent is False
    assert result.payload_encoded_or_sanitized is False
    assert result.payload_only_in_non_executable_context is False
    assert result.payload_unescaped_in_executable_context is False


def test_ambiguous_text_inside_existing_script_block():
    body = (
        "<script>var existing = true;"
        f"/* {PAYLOAD} */</script>"
    )

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.AMBIGUOUS


def test_ambiguous_javascript_uri():
    body = f'<a href="javascript:{PAYLOAD}">click</a>'

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.AMBIGUOUS


def test_ambiguous_data_uri():
    body = f'<a href="data:text/html,{PAYLOAD}">click</a>'

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.AMBIGUOUS


def test_ambiguous_conflicting_matches_in_different_buckets():
    # Same marker appears once inertly (comment) and once forming a
    # genuine executable construct elsewhere in the same document --
    # deliberately treated as ambiguous rather than picking one.
    body = (
        f"<!-- {PAYLOAD} -->"
        f'<img src="x" onerror="{PAYLOAD}">'
    )

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.AMBIGUOUS
    assert result.payload_only_in_non_executable_context is False
    assert result.payload_unescaped_in_executable_context is False


def test_ambiguous_malformed_markup_does_not_raise():
    body = f"<div <<< {PAYLOAD} >>> broken"

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=make_response(body),
    )

    assert result.bucket in (
        XssResponseBucket.AMBIGUOUS,
        XssResponseBucket.INERT_CONTEXT,
        XssResponseBucket.EXECUTABLE_CONTEXT,
    )


def test_tag_shaped_payload_inside_textarea_is_inert():
    # <textarea> is RCDATA in real HTML5: a tag-shaped payload nested
    # inside it is literal text, never a real element, and never
    # executes. HTMLParser does not natively treat <textarea> as raw
    # text (only <script>/<style> are CDATA_CONTENT_ELEMENTS by
    # default), so without special handling the nested "<script>"
    # would be misparsed as a genuine start tag.
    payload = f"<script>{PAYLOAD}</script>"
    body = f"<textarea>{payload}</textarea>"

    result = analyze_reflected_xss_response(
        payload=payload,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.INERT_CONTEXT
    assert result.payload_only_in_non_executable_context is True
    assert result.payload_unescaped_in_executable_context is False


def test_tag_shaped_payload_inside_title_is_inert():
    payload = f"<script>{PAYLOAD}</script>"
    body = f"<title>{payload}</title>"

    result = analyze_reflected_xss_response(
        payload=payload,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.INERT_CONTEXT
    assert result.payload_only_in_non_executable_context is True
    assert result.payload_unescaped_in_executable_context is False


def test_payload_reflected_into_unrelated_script_tag_attribute_is_inert():
    # The payload lands as an ordinary (non-event-handler) attribute
    # value on a pre-existing <script> tag. This must not be
    # misclassified as "payload created a new script element".
    body = f'<script src="/app.js" data-x="{PAYLOAD}"></script>'

    result = analyze_reflected_xss_response(
        payload=PAYLOAD,
        response=make_response(body),
    )

    assert result.bucket == XssResponseBucket.INERT_CONTEXT
    assert result.payload_unescaped_in_executable_context is False


def test_empty_payload_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        analyze_reflected_xss_response(
            payload="",
            response=make_response("<html></html>"),
        )


def test_csp_absent_is_permissive():
    assert _csp_permits_inline_script({}) is True


def test_csp_present_without_unsafe_inline_blocks():
    assert (
        _csp_permits_inline_script(
            {"Content-Security-Policy": "default-src 'self'"}
        )
        is False
    )


def test_csp_header_name_is_case_insensitive():
    assert (
        _csp_permits_inline_script(
            {
                "content-security-policy": (
                    "script-src 'unsafe-inline'"
                )
            }
        )
        is True
    )
