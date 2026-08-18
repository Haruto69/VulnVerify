"""
Conservative, response-only evidence analysis for REFLECTED XSS
verification.

This module never claims that a browser would execute anything. It
only structurally classifies where an injected payload landed in an
HTTP response body, using Python's stdlib html.parser.HTMLParser as a
tokenizer -- not as a general exploitability detector.

Closed taxonomy (exactly five buckets; nothing else is claimed):

1. ABSENT               -- payload does not appear in the body at all
                            (raw or HTML-escaped).
2. ENCODED_OR_SANITIZED  -- only the HTML-entity-escaped form of the
                            payload appears; the raw form does not.
3. INERT_CONTEXT         -- the raw payload appears, but only inside
                            one of exactly three structurally-provable
                            non-executable containers: an HTML
                            comment, an RCDATA element (<textarea>,
                            <title>), or a normal (non-event-handler)
                            attribute value that does not break out of
                            its quotes.
4. EXECUTABLE_CONTEXT    -- the raw payload appears, and HTMLParser
                            confirms it forms one of exactly two
                            structurally-provable executable
                            constructs: a brand-new <script> element
                            (the payload itself supplies the "<script"
                            opening), or a recognized inline
                            event-handler attribute (onerror, onload,
                            etc.) whose value contains the payload.
5. AMBIGUOUS             -- anything else: parser failure, the
                            payload split across multiple parser
                            events, plain-text-node reflection outside
                            the three named inert containers, text
                            inside an existing (not payload-created)
                            <script>/<style> block, javascript:/data:
                            URIs, the payload forming an attribute
                            *name*, or conflicting matches in more
                            than one distinct bucket. No positive or
                            negative evidence flag is set for this
                            bucket; it can only ever push the
                            aggregate classification toward
                            INCONCLUSIVE, never toward a false
                            TRUE_POSITIVE or FALSE_POSITIVE.

A match only counts when the complete payload string appears intact,
unbroken, within a single parser event's associated text (one
starttag's raw source, one attribute value, one comment body, or one
RCDATA data chunk). This is what keeps partial/broken-out payloads
from being misattributed to a bucket.

CSP interference is evaluated independently from the response
headers, not from the body, and is a simplified check (presence of
'unsafe-inline' in script-src/default-src) -- it does not attempt
nonce or hash matching.
"""

from dataclasses import dataclass
from html.parser import HTMLParser

from backend.models.replay_result import ReplayResponse


EVENT_HANDLER_ATTRIBUTES = frozenset(
    {
        "onerror",
        "onload",
        "onclick",
        "onmouseover",
        "onmouseenter",
        "onmouseleave",
        "onfocus",
        "onblur",
        "onchange",
        "onsubmit",
        "onkeydown",
        "onkeyup",
        "oninput",
        "onwheel",
    }
)

_RCDATA_ELEMENTS = frozenset({"textarea", "title"})

_URI_BEARING_ATTRIBUTES = frozenset(
    {"href", "src", "action", "formaction"}
)

_DANGEROUS_URI_SCHEMES = ("javascript:", "data:")


class XssResponseBucket:
    ABSENT = "ABSENT"
    ENCODED_OR_SANITIZED = "ENCODED_OR_SANITIZED"
    INERT_CONTEXT = "INERT_CONTEXT"
    EXECUTABLE_CONTEXT = "EXECUTABLE_CONTEXT"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True)
class XssResponseAnalysis:
    bucket: str

    payload_reflected_or_rendered: bool = False
    payload_unescaped_in_executable_context: bool = False
    payload_encoded_or_sanitized: bool = False
    payload_absent: bool = False
    payload_only_in_non_executable_context: bool = False

    no_interfering_csp_encoding_or_sanitization: bool = False


def analyze_reflected_xss_response(
    *,
    payload: str,
    response: ReplayResponse,
) -> XssResponseAnalysis:
    """
    Classify one REFLECTED XSS replay response into exactly one of
    the five buckets above. Never guesses: an unresolved structural
    placement always falls to AMBIGUOUS rather than being assigned to
    INERT_CONTEXT or EXECUTABLE_CONTEXT.
    """

    if not payload:
        raise ValueError(
            "analyze_reflected_xss_response() requires a non-empty payload"
        )

    body = response.body
    csp_permissive = _csp_permits_inline_script(response.headers)

    if body is None or payload not in body:
        if body is not None and _payload_is_html_escaped(payload, body):
            return XssResponseAnalysis(
                bucket=XssResponseBucket.ENCODED_OR_SANITIZED,
                payload_encoded_or_sanitized=True,
            )

        return XssResponseAnalysis(
            bucket=XssResponseBucket.ABSENT,
            payload_absent=True,
        )

    resolved_bucket = _locate_structural_placement(
        payload=payload,
        body=body,
    )

    if resolved_bucket == XssResponseBucket.EXECUTABLE_CONTEXT:
        return XssResponseAnalysis(
            bucket=XssResponseBucket.EXECUTABLE_CONTEXT,
            payload_reflected_or_rendered=True,
            payload_unescaped_in_executable_context=True,
            no_interfering_csp_encoding_or_sanitization=csp_permissive,
        )

    if resolved_bucket == XssResponseBucket.INERT_CONTEXT:
        return XssResponseAnalysis(
            bucket=XssResponseBucket.INERT_CONTEXT,
            payload_reflected_or_rendered=True,
            payload_only_in_non_executable_context=True,
            no_interfering_csp_encoding_or_sanitization=csp_permissive,
        )

    return XssResponseAnalysis(
        bucket=XssResponseBucket.AMBIGUOUS,
        no_interfering_csp_encoding_or_sanitization=csp_permissive,
    )


def _payload_is_html_escaped(payload: str, body: str) -> bool:
    for variant in _html_escape_variants(payload):
        if variant in body:
            return True

    return False


def _html_escape_variants(payload: str) -> list[str]:
    named = (
        payload.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )

    numeric = (
        payload.replace("&", "&#38;")
        .replace("<", "&#60;")
        .replace(">", "&#62;")
        .replace('"', "&#34;")
        .replace("'", "&#39;")
    )

    return [named, numeric]


def _csp_permits_inline_script(headers: dict[str, str]) -> bool:
    csp_value = None

    for name, value in headers.items():
        if name.lower() == "content-security-policy":
            csp_value = value
            break

    if not csp_value:
        return True

    directives: dict[str, list[str]] = {}

    for directive in csp_value.split(";"):
        tokens = directive.strip().split()

        if not tokens:
            continue

        directives[tokens[0].lower()] = tokens[1:]

    relevant_sources = (
        directives.get("script-src")
        or directives.get("default-src")
    )

    if relevant_sources is None:
        return True

    for source in relevant_sources:
        if source.strip("'\"").lower() == "unsafe-inline":
            return True

    return False


def _locate_structural_placement(
    *,
    payload: str,
    body: str,
) -> str | None:
    locator = _MarkerLocator(payload)

    try:
        locator.feed(body)
        locator.close()
    except Exception:
        return None

    return locator.resolved_bucket()


class _MarkerLocator(HTMLParser):
    """
    Walks the full response body once, recording every structurally-
    complete placement of the payload it can attribute to a specific,
    named bucket. If the whole-document scan finds placements in more
    than one distinct bucket, or none at all, the result is
    unresolved (ambiguous) rather than guessed.
    """

    # By default HTMLParser only treats <script>/<style> as raw-text
    # (CDATA) content elements; <textarea>/<title> are RCDATA in real
    # HTML5 but HTMLParser does NOT special-case them, so without this
    # override a tag-shaped payload nested inside <textarea>/<title>
    # would be tokenized as genuine nested tags instead of literal
    # text, defeating the INERT_CONTEXT classification below.
    CDATA_CONTENT_ELEMENTS = ("script", "style", "textarea", "title")

    def __init__(self, payload: str):
        super().__init__(convert_charrefs=True)

        self._payload = payload
        self._open_raw_text_elements: list[str] = []
        self._resolutions: list[str] = []

    def resolved_bucket(self) -> str | None:
        distinct = set(self._resolutions)

        if len(distinct) == 1:
            return next(iter(distinct))

        return None

    def handle_starttag(self, tag, attrs):
        tag_lower = tag.lower()

        self._evaluate_starttag(tag_lower, attrs)

        if tag_lower in ("script", "style") or tag_lower in _RCDATA_ELEMENTS:
            self._open_raw_text_elements.append(tag_lower)

    def handle_startendtag(self, tag, attrs):
        # Self-closing form (<tag ... />): evaluate as a start tag.
        # No matching end tag will follow, so nothing is pushed onto
        # _open_raw_text_elements.
        self._evaluate_starttag(tag.lower(), attrs)

    def handle_endtag(self, tag):
        tag_lower = tag.lower()

        for index in range(len(self._open_raw_text_elements) - 1, -1, -1):
            if self._open_raw_text_elements[index] == tag_lower:
                del self._open_raw_text_elements[index]
                break

    def handle_data(self, data):
        if self._payload not in data:
            return

        if self._open_raw_text_elements:
            current = self._open_raw_text_elements[-1]

            if current in _RCDATA_ELEMENTS:
                self._resolutions.append(XssResponseBucket.INERT_CONTEXT)

            # current in ("script", "style"): text inside an existing
            # block is deliberately left unresolved (ambiguous) -- we
            # cannot prove the payload created this block, and text
            # reflected into an *existing* script/style block requires
            # JS/CSS-context analysis this module does not perform.
            return

        # Plain text node, outside any tracked container. Not one of
        # the three named inert sub-cases, so deliberately left
        # unresolved rather than assumed inert.

    def handle_comment(self, data):
        if self._payload in data:
            self._resolutions.append(XssResponseBucket.INERT_CONTEXT)

    def _evaluate_starttag(self, tag_lower, attrs):
        # Case A: the parser's own opening-tag syntax (e.g. "<script>")
        # is itself wholly contained within the attacker payload --
        # proof the payload supplied this tag's opening bytes, not
        # just that the payload happened to land inside an existing
        # tag somewhere. Checked in this direction deliberately: the
        # reverse (payload contained in the tag source) would also
        # match innocuous cases like the payload sitting in an
        # attribute value of an unrelated, pre-existing <script> tag.
        if tag_lower == "script":
            raw_source = self.get_starttag_text() or ""

            if raw_source and raw_source in self._payload:
                self._resolutions.append(
                    XssResponseBucket.EXECUTABLE_CONTEXT
                )

        # Case B: the payload appears as the value of a parsed
        # attribute on this tag (regardless of which tag or whether
        # the payload created the tag itself).
        matched_event_handler = False
        matched_plain_attribute = False

        for name, value in attrs:
            if value is None or self._payload not in value:
                continue

            name_lower = name.lower()

            if name_lower in EVENT_HANDLER_ATTRIBUTES:
                matched_event_handler = True
            elif (
                name_lower in _URI_BEARING_ATTRIBUTES
                and value.strip().lower().startswith(
                    _DANGEROUS_URI_SCHEMES
                )
            ):
                # javascript:/data: URIs are deliberately not
                # claimed as inert or executable: whether this
                # actually runs depends on user interaction and
                # element-specific semantics (click vs. auto-load)
                # that response-only analysis cannot resolve.
                pass
            else:
                matched_plain_attribute = True

        if matched_event_handler:
            self._resolutions.append(XssResponseBucket.EXECUTABLE_CONTEXT)
        elif matched_plain_attribute:
            self._resolutions.append(XssResponseBucket.INERT_CONTEXT)

        # Otherwise the payload was not attributable to a single
        # attribute value or to a new <script> element -- deliberately
        # left unresolved.
