"""
Unit tests for backend/verification/csrf_candidate_detection.py in
complete isolation from the ZAP HAR parser -- every test here builds
plain HAR-shaped entry dicts directly, exactly as
find_csrf_candidates() expects to receive them.
"""

from backend.verification.csrf_candidate_detection import (
    extract_forms,
    find_csrf_candidates,
)


def make_html_entry(
    url: str,
    html: str,
    cookies: dict[str, str] | None = None,
) -> dict:
    return {
        "request": {
            "method": "GET",
            "url": url,
            "queryString": [],
            "cookies": [
                {"name": name, "value": value}
                for name, value in (cookies or {}).items()
            ],
        },
        "response": {
            "status": 200,
            "content": {"mimeType": "text/html", "text": html},
        },
    }


def make_get_entry(
    url: str,
    query: dict[str, str],
    cookies: dict[str, str] | None = None,
) -> dict:
    return {
        "request": {
            "method": "GET",
            "url": url,
            "queryString": [
                {"name": name, "value": value}
                for name, value in query.items()
            ],
            "cookies": [
                {"name": name, "value": value}
                for name, value in (cookies or {}).items()
            ],
        },
        "response": {
            "status": 200,
            "content": {"mimeType": "text/html", "text": "<html></html>"},
        },
    }


def make_post_entry(url: str, params: dict[str, str]) -> dict:
    return {
        "request": {
            "method": "POST",
            "url": url,
            "queryString": [],
            "postData": {
                "mimeType": "application/x-www-form-urlencoded",
                "params": [
                    {"name": name, "value": value}
                    for name, value in params.items()
                ],
            },
        },
        "response": {
            "status": 200,
            "content": {"mimeType": "text/html", "text": ""},
        },
    }


TOKENLESS_GET_FORM_HTML = (
    "<html><body><form action=\"#\" method=\"GET\">"
    "<input name=\"password_new\">"
    "<input name=\"password_conf\">"
    "<input type=\"submit\" name=\"Change\" value=\"Change\">"
    "</form></body></html>"
)

TOKEN_PROTECTED_FORM_HTML = (
    "<html><body><form action=\"/security.php\" method=\"POST\">"
    "<input type=\"hidden\" name=\"csrf_token\" value=\"abc123\">"
    "<select name=\"security_level\"></select>"
    "<input type=\"submit\" name=\"seclev_submit\" value=\"Submit\">"
    "</form></body></html>"
)


# ---------------------------------------------------------------------
# extract_forms
# ---------------------------------------------------------------------


def test_extract_forms_reads_method_action_and_fields():
    forms = extract_forms(
        html=TOKENLESS_GET_FORM_HTML,
        source_url="http://127.0.0.1/DVWA/vulnerabilities/csrf/",
        source_entry_index=0,
    )

    assert len(forms) == 1
    form = forms[0]

    assert form.method == "GET"
    assert form.action_url == "http://127.0.0.1/DVWA/vulnerabilities/csrf/"
    assert form.field_names == frozenset(
        {"password_new", "password_conf", "Change"}
    )
    assert form.has_anti_csrf_token is False


def test_extract_forms_detects_known_anti_csrf_token_field():
    forms = extract_forms(
        html=TOKEN_PROTECTED_FORM_HTML,
        source_url="http://127.0.0.1/DVWA/security.php",
        source_entry_index=0,
    )

    assert len(forms) == 1
    assert forms[0].has_anti_csrf_token is True


def test_extract_forms_on_malformed_html_does_not_raise():
    forms = extract_forms(
        html="<html><body><form method=GET",
        source_url="http://example.test/",
        source_entry_index=0,
    )

    # No assertion on the exact result -- only that malformed HTML
    # never raises. html.parser.HTMLParser is itself forgiving.
    assert isinstance(forms, list)


# ---------------------------------------------------------------------
# find_csrf_candidates -- positive case
# ---------------------------------------------------------------------


def test_finds_candidate_for_tokenless_form_with_matching_request():
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
        ),
        make_get_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            {
                "password_new": "meow",
                "password_conf": "meow",
                "Change": "Change",
            },
        ),
    ]

    candidates = find_csrf_candidates(entries)

    assert len(candidates) == 1
    candidate = candidates[0]

    assert candidate.request_entry_index == 1
    assert set(candidate.matched_field_names) == {
        "password_new",
        "password_conf",
        "Change",
    }


# ---------------------------------------------------------------------
# E: form containing a real anti-CSRF token is ignored
# ---------------------------------------------------------------------


def test_form_with_anti_csrf_token_produces_no_candidate():
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/security.php",
            TOKEN_PROTECTED_FORM_HTML,
        ),
        make_post_entry(
            "http://127.0.0.1/DVWA/security.php",
            {
                "csrf_token": "abc123",
                "security_level": "low",
                "seclev_submit": "Submit",
            },
        ),
    ]

    candidates = find_csrf_candidates(entries)

    assert candidates == []


# ---------------------------------------------------------------------
# F: different path is not matched
# ---------------------------------------------------------------------


def test_request_to_a_different_path_is_not_matched():
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
        ),
        make_get_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/other/",
            {
                "password_new": "meow",
                "password_conf": "meow",
                "Change": "Change",
            },
        ),
    ]

    candidates = find_csrf_candidates(entries)

    assert candidates == []


# ---------------------------------------------------------------------
# G: different method is not matched
# ---------------------------------------------------------------------


def test_request_with_a_different_method_is_not_matched():
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
        ),
        make_post_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            {
                "password_new": "meow",
                "password_conf": "meow",
                "Change": "Change",
            },
        ),
    ]

    candidates = find_csrf_candidates(entries)

    assert candidates == []


# ---------------------------------------------------------------------
# H: similar-but-not-identical parameter sets are not incorrectly
# matched (extra, unexpected parameter not declared by the form)
# ---------------------------------------------------------------------


def test_request_with_unexpected_extra_parameter_is_not_matched():
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
        ),
        make_get_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            {
                "password_new": "meow",
                "password_conf": "meow",
                "Change": "Change",
                "unexpected_extra_field": "1",
            },
        ),
    ]

    candidates = find_csrf_candidates(entries)

    assert candidates == []


def test_request_missing_some_declared_fields_is_still_matched():
    # A legitimately-absent field (e.g. an unchecked checkbox) must
    # not block matching -- only unexpected extra parameters do.
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
        ),
        make_get_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            {"password_new": "meow"},
        ),
    ]

    candidates = find_csrf_candidates(entries)

    assert len(candidates) == 1


def test_request_with_no_parameters_is_not_matched():
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
        ),
        make_get_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            {},
        ),
    ]

    candidates = find_csrf_candidates(entries)

    assert candidates == []


# ---------------------------------------------------------------------
# I: query parameter ordering does not matter
# ---------------------------------------------------------------------


def test_parameter_ordering_does_not_affect_matching():
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
        ),
        make_get_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            {
                "Change": "Change",
                "password_conf": "meow",
                "password_new": "meow",
            },
        ),
    ]

    candidates = find_csrf_candidates(entries)

    assert len(candidates) == 1


# ---------------------------------------------------------------------
# J: URL encoding is handled correctly
# ---------------------------------------------------------------------


def test_url_encoded_query_string_is_handled_via_fallback_parsing():
    # No queryString[] array supplied -- forces the fallback path
    # that parses the raw (percent-encoded) URL query string.
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
        ),
        {
            "request": {
                "method": "GET",
                "url": (
                    "http://127.0.0.1/DVWA/vulnerabilities/csrf/"
                    "?password_new=meow%20meow&password_conf=meow"
                    "%20meow&Change=Change"
                ),
            },
            "response": {
                "status": 200,
                "content": {"mimeType": "text/html", "text": ""},
            },
        },
    ]

    candidates = find_csrf_candidates(entries)

    assert len(candidates) == 1
    assert set(candidates[0].matched_field_names) == {
        "password_new",
        "password_conf",
        "Change",
    }


# ---------------------------------------------------------------------
# Duplicate parameters do not break matching (only names are compared)
# ---------------------------------------------------------------------


def test_duplicate_parameter_values_do_not_break_matching():
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
        ),
        {
            "request": {
                "method": "GET",
                "url": (
                    "http://127.0.0.1/DVWA/vulnerabilities/csrf/"
                ),
                "queryString": [
                    {"name": "password_new", "value": "meow"},
                    {"name": "password_new", "value": "meow2"},
                    {"name": "password_conf", "value": "meow"},
                    {"name": "Change", "value": "Change"},
                ],
            },
            "response": {
                "status": 200,
                "content": {"mimeType": "text/html", "text": ""},
            },
        },
    ]

    candidates = find_csrf_candidates(entries)

    assert len(candidates) == 1


# ---------------------------------------------------------------------
# session_cookie_consistent
# ---------------------------------------------------------------------


def test_matching_session_cookie_on_form_and_request_is_consistent():
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
            cookies={"PHPSESSID": "abc123"},
        ),
        make_get_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            {
                "password_new": "meow",
                "password_conf": "meow",
                "Change": "Change",
            },
            cookies={"PHPSESSID": "abc123"},
        ),
    ]

    candidates = find_csrf_candidates(entries)

    assert len(candidates) == 1
    assert candidates[0].session_cookie_consistent is True


def test_no_cookies_at_all_is_not_session_consistent():
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
        ),
        make_get_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            {
                "password_new": "meow",
                "password_conf": "meow",
                "Change": "Change",
            },
        ),
    ]

    candidates = find_csrf_candidates(entries)

    assert len(candidates) == 1
    assert candidates[0].session_cookie_consistent is False


def test_unrecognized_cookie_name_is_not_session_consistent():
    # A cookie is present and even matches in value, but its name is
    # not a recognized session-cookie name -- must not be treated as
    # session evidence just because *some* cookie matched.
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
            cookies={"marketing_id": "abc123"},
        ),
        make_get_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            {
                "password_new": "meow",
                "password_conf": "meow",
                "Change": "Change",
            },
            cookies={"marketing_id": "abc123"},
        ),
    ]

    candidates = find_csrf_candidates(entries)

    assert len(candidates) == 1
    assert candidates[0].session_cookie_consistent is False


def test_session_cookie_value_mismatch_is_not_session_consistent():
    # Recognized cookie name, but the value differs between the
    # form-load request and the submission -- not the same session.
    entries = [
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
            cookies={"PHPSESSID": "abc123"},
        ),
        make_get_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            {
                "password_new": "meow",
                "password_conf": "meow",
                "Change": "Change",
            },
            cookies={"PHPSESSID": "different-session"},
        ),
    ]

    candidates = find_csrf_candidates(entries)

    assert len(candidates) == 1
    assert candidates[0].session_cookie_consistent is False


# ---------------------------------------------------------------------
# Only entries AFTER the form's own source entry are eligible
# ---------------------------------------------------------------------


def test_matching_request_before_the_form_is_not_used():
    entries = [
        make_get_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            {
                "password_new": "meow",
                "password_conf": "meow",
                "Change": "Change",
            },
        ),
        make_html_entry(
            "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            TOKENLESS_GET_FORM_HTML,
        ),
    ]

    candidates = find_csrf_candidates(entries)

    assert candidates == []
