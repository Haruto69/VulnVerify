"""
Structural CSRF candidate detection from captured HTTP traffic
(HAR entries).

This module is deliberately self-contained: it operates only on plain
HAR-shaped dicts (never on NormalizedFinding, never on a parser), so
it can be tested and reasoned about in complete isolation from the
ZAP HAR parser that consumes it (backend/parsers/zap_har.py).

What this module does NOT do, on purpose:
  - It never inspects a URL or response body for the substring
    "csrf", or a parameter name for "password". Those are exactly the
    brittle, false-positive-prone shortcuts this feature must avoid.
  - It never decides TRUE_POSITIVE/FALSE_POSITIVE. It only decides
    "this HTML form + this later request are structurally consistent
    enough to be worth handing to the existing, unmodified CSRF
    verifier." Exploitability remains that verifier's job alone.
  - It never requires a session cookie to produce a candidate. A
    cookie is not proof of authenticated privilege (and its absence
    is not proof of the opposite) -- that judgment belongs to the
    CSRF verifier's own authentication/session checks, not here.

Detection algorithm, per candidate form:
  1. Parse every HTML response in the HAR for <form> elements
     (backend/verification/csrf_candidate_detection._FormExtractor),
     recording each form's resolved action URL, method, and declared
     fields (name + input type + hidden-ness).
  2. Discard forms that contain a recognized anti-CSRF token field
     (hidden input whose name matches a bounded, well-known allowlist
     of real framework token field names -- not a guess).
  3. For each remaining (tokenless) form, search later HAR entries
     for a request that structurally matches: same origin, same
     resolved path, same HTTP method, and a parameter-name set that
     is a non-empty subset of the form's own declared field names
     (tolerating fields the browser legitimately omitted -- e.g.
     unchecked checkboxes -- without tolerating an unrelated request
     that merely happens to share a path).
"""

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import (
    parse_qs,
    urljoin,
    urlsplit,
    urlunsplit,
)

# Real, well-known anti-CSRF token field names used by common web
# frameworks. Bounded and explicit on purpose -- this is structural
# evidence (a specific, recognized hidden field), not a guess based
# on any field merely containing the word "csrf" or "token".
KNOWN_ANTI_CSRF_TOKEN_FIELD_NAMES = {
    "csrf_token",
    "csrfmiddlewaretoken",
    "_csrf",
    "authenticity_token",
    "__requestverificationtoken",
}

# Real, well-known session-cookie names used by common web servers and
# frameworks. Bounded and explicit for the same reason as
# KNOWN_ANTI_CSRF_TOKEN_FIELD_NAMES above: this lets us recognize a
# specific, recognized session identifier rather than assuming any
# cookie at all implies a session. Matched case-insensitively.
KNOWN_SESSION_COOKIE_NAMES = {
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
    "connect.sid",
    "sessionid",
}


@dataclass(frozen=True)
class FormField:
    name: str
    input_type: str  # lowercased; "text" if unspecified
    is_hidden: bool


@dataclass(frozen=True)
class DetectedForm:
    source_url: str  # the page URL the form was found on
    source_entry_index: int
    action_url: str  # resolved absolute action URL, no query/fragment
    method: str  # uppercased
    fields: tuple[FormField, ...] = field(default_factory=tuple)

    @property
    def field_names(self) -> frozenset[str]:
        return frozenset(f.name for f in self.fields)

    @property
    def has_anti_csrf_token(self) -> bool:
        return any(
            f.is_hidden
            and f.name.strip().lower()
            in KNOWN_ANTI_CSRF_TOKEN_FIELD_NAMES
            for f in self.fields
        )


@dataclass(frozen=True)
class CsrfCandidate:
    form: DetectedForm
    request_entry_index: int
    matched_field_names: tuple[str, ...]
    # True only when the matched request carries a cookie whose name
    # is a recognized session-cookie name (KNOWN_SESSION_COOKIE_NAMES)
    # with the SAME value as a cookie of that same name already
    # present on the request that loaded the source form. This is
    # structural evidence that the form was viewed and submitted
    # within one continuous session -- not merely "a cookie existed",
    # which is why an arbitrary/unrecognized cookie name, or a
    # session-cookie name whose value differs between the two
    # requests, does not set this True.
    session_cookie_consistent: bool = False


class _FormExtractor(HTMLParser):
    """
    Minimal, dependency-free <form> extractor.

    Deliberately tolerant of malformed HTML (no strict nesting
    validation) -- this is evidence extraction, not an HTML validator.
    Every <input>/<select>/<textarea> encountered while a <form> is
    open is recorded as one of that form's declared fields, including
    submit-type inputs: a GET form's submit button
    (<input type="submit" name="Change" value="Change">) contributes
    its own name to the resulting query string on submission, so it
    is a real, matchable field -- not noise to discard.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attrs_map = {
            name.lower(): (value or "")
            for name, value in attrs
            if name
        }

        if tag == "form":
            self._current = {
                "action": attrs_map.get("action", ""),
                "method": (
                    attrs_map.get("method") or "GET"
                ).strip().upper(),
                "fields": [],
            }
            self.forms.append(self._current)
            return

        if (
            tag in ("input", "select", "textarea")
            and self._current is not None
        ):
            name = attrs_map.get("name")

            if not name:
                return

            input_type = (
                attrs_map.get("type", "text") or "text"
            ).strip().lower()

            self._current["fields"].append(
                FormField(
                    name=name,
                    input_type=input_type,
                    is_hidden=(input_type == "hidden"),
                )
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None


def extract_forms(
    html: str,
    source_url: str,
    source_entry_index: int,
) -> list[DetectedForm]:
    """
    Extract every <form> in an HTML document as a DetectedForm.

    Never raises on malformed HTML -- html.parser.HTMLParser is
    already forgiving, and a document that yields no forms simply
    yields an empty list.
    """

    parser = _FormExtractor()
    parser.feed(html)
    parser.close()

    forms = []

    for raw_form in parser.forms:
        action_url = _resolve_form_action(
            source_url=source_url,
            action=raw_form["action"],
        )

        forms.append(
            DetectedForm(
                source_url=source_url,
                source_entry_index=source_entry_index,
                action_url=action_url,
                method=raw_form["method"],
                fields=tuple(raw_form["fields"]),
            )
        )

    return forms


def _resolve_form_action(source_url: str, action: str) -> str:
    """
    Resolve a (possibly relative, possibly empty, possibly "#") form
    action against the page URL it was found on, and strip the query
    string and fragment -- both action="" and action="#" mean "submit
    back to this page" per the HTML spec, and the query string on an
    action URL (if any) is not what carries the submitted fields, so
    it plays no role in structural path matching.
    """

    resolved = urljoin(source_url, action or "")
    parts = urlsplit(resolved)

    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path or "/", "", "")
    )


def _resolve_request_path(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path or "/", "", "")
    )


def _request_parameter_names(entry: dict) -> frozenset[str]:
    """
    Parameter names actually submitted by one HAR request entry --
    query string for any method, plus POST body parameters when the
    HAR captured them. Duplicate parameter values collapse to a
    single name naturally (only names are compared, never values),
    so repeated parameters never confuse matching.
    """

    request = entry.get("request") or {}
    names: set[str] = set()

    query_string = request.get("queryString")

    if isinstance(query_string, list):
        for item in query_string:
            name = item.get("name") if isinstance(item, dict) else None
            if isinstance(name, str):
                names.add(name)
    else:
        # Fall back to parsing the URL's own query string. HAR's own
        # queryString[] array already carries decoded values, so this
        # fallback path is the only place URL-encoding is handled
        # manually -- parse_qs decodes it the same way either way.
        query = urlsplit(request.get("url", "")).query
        for name in parse_qs(query, keep_blank_values=True):
            names.add(name)

    post_data = request.get("postData")

    if isinstance(post_data, dict):
        params = post_data.get("params")

        if isinstance(params, list):
            for item in params:
                name = (
                    item.get("name") if isinstance(item, dict) else None
                )
                if isinstance(name, str):
                    names.add(name)
        else:
            text = post_data.get("text")

            if isinstance(text, str) and text:
                for name in parse_qs(text, keep_blank_values=True):
                    names.add(name)

    return frozenset(names)


def _entry_cookies(entry: dict) -> dict[str, str]:
    request = entry.get("request") or {}
    cookies = request.get("cookies")
    result: dict[str, str] = {}

    if not isinstance(cookies, list):
        return result

    for item in cookies:
        if not isinstance(item, dict):
            continue

        name = item.get("name")
        value = item.get("value")

        if isinstance(name, str) and isinstance(value, str):
            result[name] = value

    return result


def _session_cookie_consistent(
    form: DetectedForm,
    entries: list[dict],
    request_entry_index: int,
) -> bool:
    """
    True only when the matched request and the request that loaded
    the source form share a recognized session cookie with an
    identical value -- see CsrfCandidate.session_cookie_consistent.
    """

    form_entry_cookies = _entry_cookies(
        entries[form.source_entry_index]
    )
    request_entry_cookies = _entry_cookies(
        entries[request_entry_index]
    )

    for name, value in request_entry_cookies.items():
        if name.strip().lower() not in KNOWN_SESSION_COOKIE_NAMES:
            continue

        if form_entry_cookies.get(name) == value:
            return True

    return False


def _entry_method(entry: dict) -> str:
    request = entry.get("request") or {}
    return str(request.get("method", "")).strip().upper()


def _entry_url(entry: dict) -> str:
    request = entry.get("request") or {}
    return str(request.get("url", ""))


def find_csrf_candidates(
    entries: list[dict],
) -> list[CsrfCandidate]:
    """
    Find CSRF candidates across a list of HAR entries.

    Two-pass process:
      1. Extract every HTML response's forms.
      2. For each tokenless form, search entries AFTER the form's own
         source entry (later in the capture, matching the natural
         "load the page, then submit it" ordering) for a structurally
         matching request. The first match is taken -- one candidate
         per tokenless form, not one per every loosely-similar
         request, to avoid duplicate near-identical findings for the
         same real-world submission.
    """

    forms: list[DetectedForm] = []

    for index, entry in enumerate(entries):
        response = entry.get("response") or {}
        content = response.get("content") or {}
        mime_type = str(content.get("mimeType", ""))

        if "html" not in mime_type.lower():
            continue

        body = content.get("text")

        if not isinstance(body, str) or not body:
            continue

        forms.extend(
            extract_forms(
                html=body,
                source_url=_entry_url(entry),
                source_entry_index=index,
            )
        )

    candidates: list[CsrfCandidate] = []

    for form in forms:
        if form.has_anti_csrf_token:
            continue

        if not form.field_names:
            continue

        match = _find_matching_request(
            form=form,
            entries=entries,
        )

        if match is None:
            continue

        entry_index, matched_names = match

        candidates.append(
            CsrfCandidate(
                form=form,
                request_entry_index=entry_index,
                matched_field_names=tuple(sorted(matched_names)),
                session_cookie_consistent=_session_cookie_consistent(
                    form=form,
                    entries=entries,
                    request_entry_index=entry_index,
                ),
            )
        )

    return candidates


def _find_matching_request(
    form: DetectedForm,
    entries: list[dict],
) -> tuple[int, frozenset[str]] | None:
    form_origin_and_path = _resolve_request_path(form.action_url)

    for index in range(form.source_entry_index + 1, len(entries)):
        entry = entries[index]

        if _entry_method(entry) != form.method:
            continue

        if _resolve_request_path(_entry_url(entry)) != (
            form_origin_and_path
        ):
            continue

        request_names = _request_parameter_names(entry)

        if not request_names:
            continue

        # Tolerate fields the form declared but the browser legitimately
        # omitted (e.g. an unchecked checkbox) -- the submitted names
        # must not include anything the form didn't declare, but they
        # need not include everything the form declared.
        if not request_names.issubset(form.field_names):
            continue

        return index, request_names

    return None
