import base64

import pytest

from backend.models.normalized_finding import VulnerabilityCategory
from backend.parsers.burp import BurpParser


REAL_BURP_FIXTURE = "tests/fixtures/burp_real_sample.xml"


def read_fixture(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


def make_issue_xml(
    *,
    name: str = "SQL Injection",
    host: str = "example.test",
    path: str = "/p",
    location: str | None = "/p",
    severity: str = "High",
    confidence: str | None = "Firm",
    serial_number: str | None = "12345",
    extra: str = "",
) -> bytes:
    """
    Build a small, single-<issue> Burp report. Defaults to a
    SQL Injection issue name so tests exercise fields other than
    category mapping without depending on the extended-category
    mapping behavior (see
    test_extended_category_names_map_to_dedicated_members).
    """

    location_xml = (
        f"<location>{location}</location>"
        if location is not None
        else ""
    )
    confidence_xml = (
        f"<confidence>{confidence}</confidence>"
        if confidence is not None
        else ""
    )
    serial_xml = (
        f"<serialNumber>{serial_number}</serialNumber>"
        if serial_number is not None
        else ""
    )

    return (
        "<issues><issue>"
        f"{serial_xml}"
        f"<name>{name}</name>"
        f"<host>{host}</host>"
        f"<path>{path}</path>"
        f"{location_xml}"
        f"<severity>{severity}</severity>"
        f"{confidence_xml}"
        f"{extra}"
        "</issue></issues>"
    ).encode("utf-8")


def first_finding(content: bytes, scan_id: str = "scan-burp-001"):
    return BurpParser().parse(content=content, scan_id=scan_id)[0]


# ---------------------------------------------------------------------
# Real fixture: extended category mapping.
#
# tests/fixtures/burp_real_sample.xml contains a single Burp issue
# named "Cross-origin resource sharing". VulnerabilityCategory
# (backend/models/normalized_finding.py) defines a dedicated CORS
# member, so _map_category() maps it there directly rather than
# falling back to XSS.
# ---------------------------------------------------------------------


def test_real_fixture_parses_successfully():
    parser = BurpParser()

    findings = parser.parse(
        content=read_fixture(REAL_BURP_FIXTURE),
        scan_id="scan-burp-001",
    )

    assert len(findings) == 1
    assert (
        findings[0].vulnerability.category
        == VulnerabilityCategory.CORS
    )


@pytest.mark.parametrize(
    "issue_name,expected_category",
    [
        (
            "Cross-origin resource sharing",
            VulnerabilityCategory.CORS,
        ),
        (
            "Private IP addresses disclosed",
            VulnerabilityCategory.INFORMATION_DISCLOSURE,
        ),
        (
            "Unencrypted communications",
            VulnerabilityCategory.SECURITY_MISCONFIGURATION,
        ),
        (
            "Robots.txt file",
            VulnerabilityCategory.INFORMATIONAL,
        ),
        (
            "Some completely unrecognized Burp issue name",
            VulnerabilityCategory.OTHER,
        ),
    ],
    ids=[
        "CORS",
        "Information Disclosure",
        "Security Misconfiguration",
        "Informational",
        "OTHER (fallback)",
    ],
)
def test_extended_category_names_map_to_dedicated_members(
    issue_name, expected_category
):
    """
    Each extended category branch in _map_category() (CORS,
    Information Disclosure, Security Misconfiguration, Informational,
    and the catch-all for an unrecognized name) maps to its own
    dedicated VulnerabilityCategory member rather than falling back
    to XSS.
    """

    finding = first_finding(make_issue_xml(name=issue_name))

    assert finding.vulnerability.category == expected_category


@pytest.mark.parametrize(
    "issue_name,expected_category",
    [
        ("SQL Injection", VulnerabilityCategory.SQLI),
        ("SQL Injection (second order)", VulnerabilityCategory.SQLI),
        ("sql-injection", VulnerabilityCategory.SQLI),
        (
            "Cross-site request forgery (CSRF)",
            VulnerabilityCategory.CSRF,
        ),
        ("CSRF", VulnerabilityCategory.CSRF),
        (
            "Cross-site scripting (reflected)",
            VulnerabilityCategory.XSS,
        ),
        ("XSS", VulnerabilityCategory.XSS),
    ],
)
def test_supported_category_mapping(issue_name, expected_category):
    finding = first_finding(make_issue_xml(name=issue_name))

    assert finding.vulnerability.category == expected_category


# ---------------------------------------------------------------------
# Real fixture: request/response field extraction.
#
# The real fixture's request/response base64 payloads are reused
# verbatim in a synthetic issue whose <name> is swapped to "SQL
# Injection", so these field-extraction assertions exercise genuine,
# real-world Burp request/response data independently of which
# category the issue name happens to map to.
# ---------------------------------------------------------------------


REAL_REQUEST_B64 = (
    "R0VUIC9zb2NrZXQuaW8vP0VJTz00JnRyYW5zcG9ydD1wb2xsaW5nJnQ9UTA4cHM2aCBIVFRQ"
    "LzEuMQ0KSG9zdDogbG9jYWxob3N0OjMwMDANCkNhY2hlLUNvbnRyb2w6IG1heC1hZ2U9MA0K"
    "U2VjLUNILVVBOiAiQ2hyb21pdW0iO3Y9IjE1MCIsICJOb3Q7QT1CcmFuZCI7dj0iMjQiLCAi"
    "R29vZ2xlIENocm9tZSI7dj0iMTUwIg0KU2VjLUNILVVBLU1vYmlsZTogPzANClNlYy1DSC1V"
    "QS1QbGF0Zm9ybTogIldpbmRvd3MiDQpBY2NlcHQtTGFuZ3VhZ2U6IGVuLVVTO3E9MC45LGVu"
    "O3E9MC44DQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42"
    "NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUv"
    "MTUwLjAuMC4wIFNhZmFyaS81MzcuMzYNCkFjY2VwdDogKi8qDQpTZWMtRmV0Y2gtU2l0ZTog"
    "bm9uZQ0KU2VjLUZldGNoLU1vZGU6IG5hdmlnYXRlDQpTZWMtRmV0Y2gtVXNlcjogPzENClNl"
    "Yy1GZXRjaC1EZXN0OiBkb2N1bWVudA0KQWNjZXB0LUVuY29kaW5nOiBnemlwLCBkZWZsYXRl"
    "LCBicg0KQ29ubmVjdGlvbjogY2xvc2UNClJlZmVyZXI6IGh0dHA6Ly9sb2NhbGhvc3Q6MzAw"
    "MC8NCk9yaWdpbjogaHR0cDovL2xvY2FsaG9zdDo0MjAwDQoNCg=="
)

REAL_RESPONSE_B64 = (
    "SFRUUC8xLjEgMjAwIE9LDQpBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW46IGh0dHA6Ly9s"
    "b2NhbGhvc3Q6NDIwMA0KVmFyeTogT3JpZ2luDQpDb250ZW50LVR5cGU6IHRleHQvcGxhaW47"
    "IGNoYXJzZXQ9VVRGLTgNCkNvbnRlbnQtTGVuZ3RoOiA5Ng0KRGF0ZTogU3VuLCAxNiBBdWcg"
    "MjAyNiAwNDoyMzoyMyBHTVQNCkNvbm5lY3Rpb246IGNsb3NlDQoNCjB7InNpZCI6ImtLQjYz"
    "Mmd6VTRJV09XdV9BQVd1IiwidXBncmFkZXMiOlsid2Vic29ja2V0Il0sInBpbmdJbnRlcnZh"
    "bCI6MjUwMDAsInBpbmdUaW1lb3V0Ijo1MDAwfQ=="
)


def real_fixture_reused_as_sqli() -> bytes:
    xml = read_fixture(REAL_BURP_FIXTURE).decode("utf-8")
    return xml.replace(
        "<name>Cross-origin resource sharing</name>",
        "<name>SQL Injection</name>",
    ).encode("utf-8")


def test_real_fixture_variant_parses_to_exactly_one_finding():
    findings = BurpParser().parse(
        content=real_fixture_reused_as_sqli(),
        scan_id="scan-burp-001",
    )

    assert len(findings) == 1


def test_real_fixture_scanner_and_source_metadata():
    finding = first_finding(real_fixture_reused_as_sqli())

    assert finding.scan_id == "scan-burp-001"
    assert finding.source.scanner == "Burp"
    assert (
        finding.source.scanner_finding_id
        == "3029841365459156992"
    )
    assert finding.source.original_name == "SQL Injection"
    assert finding.vulnerability.subtype == "SQL Injection"


def test_real_fixture_severity_and_confidence():
    finding = first_finding(real_fixture_reused_as_sqli())

    assert finding.vulnerability.raw_severity == "Information"
    assert (
        finding.vulnerability.normalized_severity
        == "INFORMATIONAL"
    )
    assert finding.vulnerability.raw_confidence == "Certain"
    assert finding.vulnerability.normalized_confidence == "HIGH"


def test_real_fixture_cwe_and_references():
    finding = first_finding(real_fixture_reused_as_sqli())

    assert finding.vulnerability.cwe == "CWE-942"
    assert (
        "https://portswigger.net/web-security/cors"
        in finding.references
    )
    assert (
        "https://portswigger.net/research/"
        "exploiting-cors-misconfigurations-for-bitcoins-and-bounties"
        in finding.references
    )


def test_real_fixture_target_url_host_path():
    finding = first_finding(real_fixture_reused_as_sqli())

    assert (
        finding.target.url
        == "http://localhost:3000/socket.io/"
        "?EIO=4&transport=polling&t=Q08ps6h"
    )
    assert (
        finding.target.normalized_url
        == "http://localhost:3000/socket.io/"
    )
    assert finding.target.host == "localhost"
    assert finding.target.path == "/socket.io/"


def test_real_fixture_query_parameter_extraction():
    finding = first_finding(real_fixture_reused_as_sqli())

    assert finding.request.query_parameters == {
        "EIO": ["4"],
        "transport": ["polling"],
        "t": ["Q08ps6h"],
    }


def test_real_fixture_http_method():
    finding = first_finding(real_fixture_reused_as_sqli())

    assert finding.request.method == "GET"


def test_real_fixture_request_headers_decoded_from_base64():
    finding = first_finding(real_fixture_reused_as_sqli())

    assert finding.request.headers["host"] == "localhost:3000"
    assert (
        finding.request.headers["user-agent"].startswith(
            "Mozilla/5.0"
        )
    )
    assert finding.request.headers["connection"] == "close"
    assert (
        finding.request.headers["origin"]
        == "http://localhost:4200"
    )


def test_real_fixture_request_body_is_none_when_empty():
    finding = first_finding(real_fixture_reused_as_sqli())

    assert finding.request.body is None


def test_real_fixture_request_raw_is_the_decoded_base64_message():
    finding = first_finding(real_fixture_reused_as_sqli())

    expected_raw = base64.b64decode(
        REAL_REQUEST_B64
    ).decode("utf-8")

    assert finding.request.raw == expected_raw


def test_real_fixture_response_status_code():
    finding = first_finding(real_fixture_reused_as_sqli())

    assert finding.response is not None
    assert finding.response.status_code == 200


def test_real_fixture_response_headers_decoded_from_base64():
    finding = first_finding(real_fixture_reused_as_sqli())

    assert (
        finding.response.headers["content-type"]
        == "text/plain; charset=UTF-8"
    )
    assert finding.response.headers["content-length"] == "96"
    assert (
        finding.response.headers["access-control-allow-origin"]
        == "http://localhost:4200"
    )


def test_real_fixture_response_body_decoded_from_base64():
    finding = first_finding(real_fixture_reused_as_sqli())

    expected_body = base64.b64decode(
        REAL_RESPONSE_B64
    ).decode("utf-8").split("\r\n\r\n", 1)[1]

    assert finding.response.body == expected_body
    assert '"sid":"kKB632gzU4IWOWu_AAWu"' in finding.response.body


def test_real_fixture_response_raw_is_the_decoded_base64_message():
    finding = first_finding(real_fixture_reused_as_sqli())

    expected_raw = base64.b64decode(
        REAL_RESPONSE_B64
    ).decode("utf-8")

    assert finding.response.raw == expected_raw


def test_real_fixture_parameter_detection():
    """
    location is "/socket.io/", which contains the letter "t" -- so the
    single-character query parameter "t" is detected as the tested
    parameter. This documents the substring-matching behavior actually
    implemented in _extract_parameter(), not an invented rule.
    """

    finding = first_finding(real_fixture_reused_as_sqli())

    assert finding.target.parameter == "t"
    assert finding.target.parameter_location == "QUERY"


def test_real_fixture_evidence_is_html_cleaned_issue_detail():
    finding = first_finding(real_fixture_reused_as_sqli())

    assert finding.original_test.evidence == (
        "The application implements an HTML5 cross-origin resource "
        "sharing (CORS) policy for this request. If the application "
        "relies on network firewalls or other IP-based access "
        "controls, this policy is likely to present a security risk."
    )
    assert "<br>" not in finding.original_test.evidence
    assert finding.original_test.payload is None


def test_real_fixture_metadata_fields():
    finding = first_finding(real_fixture_reused_as_sqli())

    assert finding.metadata["burp_type"] == "2098688"
    assert finding.metadata["burp_location"] == "/socket.io/"
    assert (
        "cross-origin resource sharing"
        in finding.metadata["burp_issue_background"].lower()
    )
    assert (
        finding.metadata["burp_remediation_background"]
        is not None
    )
    assert finding.metadata["burp_response_redirected"] == "false"


# ---------------------------------------------------------------------
# Malformed / non-Burp XML
# ---------------------------------------------------------------------


def test_malformed_xml_raises_value_error():
    with pytest.raises(
        ValueError,
        match="Invalid Burp XML report",
    ):
        BurpParser().parse(
            content=b"<issues><issue><name>broken</issue></issues>",
            scan_id="scan-burp-001",
        )


def test_empty_content_raises_value_error():
    with pytest.raises(
        ValueError,
        match="Invalid Burp XML report",
    ):
        BurpParser().parse(content=b"", scan_id="scan-burp-001")


def test_non_burp_xml_raises_value_error():
    with pytest.raises(
        ValueError,
        match="XML report is not a Burp report",
    ):
        BurpParser().parse(
            content=b"<root><foo>bar</foo></root>",
            scan_id="scan-burp-001",
        )


def test_valid_xml_with_no_issue_elements_is_rejected_even_under_burp_root():
    """
    A <burp> or <issues> root is trusted implicitly (no issue
    elements required), but any other root must contain at least one
    <issue> element to be accepted.
    """

    with pytest.raises(
        ValueError,
        match="XML report is not a Burp report",
    ):
        BurpParser().parse(
            content=b"<scanReport><summary>ok</summary></scanReport>",
            scan_id="scan-burp-001",
        )


def test_burp_root_with_zero_issues_returns_empty_list():
    findings = BurpParser().parse(
        content=b"<issues></issues>",
        scan_id="scan-burp-001",
    )

    assert findings == []


# ---------------------------------------------------------------------
# Namespaced XML
# ---------------------------------------------------------------------


def test_namespaced_burp_xml_is_parsed():
    xml = (
        b'<?xml version="1.0"?>'
        b'<burp:issues xmlns:burp="http://example.test/burp">'
        b"<burp:issue>"
        b"<burp:serialNumber>999</burp:serialNumber>"
        b"<burp:name>SQL Injection</burp:name>"
        b"<burp:host>http://example.test</burp:host>"
        b"<burp:path>/x</burp:path>"
        b"<burp:severity>High</burp:severity>"
        b"<burp:confidence>Firm</burp:confidence>"
        b"</burp:issue>"
        b"</burp:issues>"
    )

    finding = first_finding(xml)

    assert finding.vulnerability.category == VulnerabilityCategory.SQLI
    assert finding.source.scanner_finding_id == "999"
    assert (
        finding.vulnerability.normalized_severity == "HIGH"
    )


def test_non_namespaced_and_namespaced_issue_elements_both_match():
    xml = (
        b"<issue><name>SQL Injection</name><host>example.test</host>"
        b"<path>/p</path><severity>High</severity></issue>"
    )

    finding = first_finding(xml)

    assert finding.vulnerability.category == VulnerabilityCategory.SQLI


# ---------------------------------------------------------------------
# Multiple issues / no deduplication
# ---------------------------------------------------------------------


def test_multiple_issues_produce_one_finding_each():
    xml = (
        b"<issues>"
        b"<issue><name>SQL Injection</name><host>a.test</host>"
        b"<path>/a</path><severity>High</severity></issue>"
        b"<issue><name>Cross-site scripting (reflected)</name>"
        b"<host>b.test</host><path>/b</path>"
        b"<severity>Medium</severity></issue>"
        b"<issue><name>Cross-site request forgery</name>"
        b"<host>c.test</host><path>/c</path>"
        b"<severity>Low</severity></issue>"
        b"</issues>"
    )

    findings = BurpParser().parse(
        content=xml,
        scan_id="scan-burp-001",
    )

    assert len(findings) == 3
    assert [
        finding.vulnerability.category
        for finding in findings
    ] == [
        VulnerabilityCategory.SQLI,
        VulnerabilityCategory.XSS,
        VulnerabilityCategory.CSRF,
    ]


def test_identical_issues_are_not_deduplicated():
    single_issue = (
        b"<issue><name>SQL Injection</name><host>example.test</host>"
        b"<path>/p</path><severity>High</severity></issue>"
    )

    xml = b"<issues>" + (single_issue * 3) + b"</issues>"

    findings = BurpParser().parse(
        content=xml,
        scan_id="scan-burp-001",
    )

    assert len(findings) == 3


def test_each_finding_gets_a_distinct_finding_id():
    single_issue = (
        b"<issue><name>SQL Injection</name><host>example.test</host>"
        b"<path>/p</path><severity>High</severity></issue>"
    )

    xml = b"<issues>" + (single_issue * 3) + b"</issues>"

    findings = BurpParser().parse(
        content=xml,
        scan_id="scan-burp-001",
    )

    assert len({finding.finding_id for finding in findings}) == 3


# ---------------------------------------------------------------------
# Missing / optional fields the implementation explicitly handles
# ---------------------------------------------------------------------


def test_missing_request_response_falls_back_to_a_synthetic_get_request():
    finding = first_finding(
        make_issue_xml(host="example.test", path="/p")
    )

    assert finding.request.method == "GET"
    assert finding.request.url == "http://example.test/p"
    assert finding.request.path == "/p"
    assert finding.response is None


def test_missing_serial_number_leaves_scanner_finding_id_none():
    finding = first_finding(
        make_issue_xml(serial_number=None)
    )

    assert finding.source.scanner_finding_id is None


def test_missing_location_leaves_parameter_unknown():
    finding = first_finding(make_issue_xml(location=None))

    assert finding.target.parameter is None
    assert finding.target.parameter_location == "UNKNOWN"


def test_missing_confidence_is_unknown():
    finding = first_finding(make_issue_xml(confidence=None))

    assert finding.vulnerability.raw_confidence is None
    assert finding.vulnerability.normalized_confidence == "UNKNOWN"


def test_missing_path_defaults_to_root():
    xml = (
        b"<issue><name>SQL Injection</name><host>example.test</host>"
        b"<severity>High</severity></issue>"
    )

    finding = first_finding(xml)

    assert finding.target.path == "/"


def test_missing_name_uses_placeholder_and_falls_back_to_other():
    """
    A missing <name> falls through to "Unknown Burp finding", which
    _map_category() cannot specifically classify, so it hits the
    OTHER catch-all as any other unrecognized issue name does.
    """

    xml = (
        b"<issue><host>example.test</host><path>/p</path>"
        b"<severity>High</severity></issue>"
    )

    finding = first_finding(xml)

    assert finding.source.original_name == "Unknown Burp finding"
    assert finding.vulnerability.category == VulnerabilityCategory.OTHER


def test_missing_vulnerability_classifications_leaves_cwe_none():
    finding = first_finding(make_issue_xml())

    assert finding.vulnerability.cwe is None


def test_missing_references_defaults_to_empty_list():
    finding = first_finding(make_issue_xml())

    assert finding.references == []


def test_missing_issue_detail_leaves_evidence_none():
    finding = first_finding(make_issue_xml())

    assert finding.original_test.evidence is None


def test_context_requirement_states_are_always_unknown():
    finding = first_finding(make_issue_xml())

    assert (
        finding.context.authentication_required == "UNKNOWN"
    )
    assert finding.context.session_required == "UNKNOWN"


# ---------------------------------------------------------------------
# Request/response construction details
# ---------------------------------------------------------------------


def test_plain_text_request_without_base64_flag():
    extra = (
        "<requestresponse>"
        "<request method=\"POST\">POST /login HTTP/1.1\r\n"
        "Host: example.test\r\nContent-Type: application/x-www-form-"
        "urlencoded\r\n\r\nuser=admin&amp;pass=secret</request>"
        "</requestresponse>"
    )

    finding = first_finding(make_issue_xml(extra=extra))

    assert finding.request.method == "POST"
    assert finding.request.body == "user=admin&pass=secret"
    assert (
        finding.request.content_type
        == "application/x-www-form-urlencoded"
    )


def test_invalid_base64_request_decodes_to_empty_and_leaves_raw_none():
    extra = (
        "<requestresponse>"
        "<request method=\"GET\" base64=\"true\">"
        "!!!not-valid-base64!!!"
        "</request>"
        "</requestresponse>"
    )

    finding = first_finding(make_issue_xml(extra=extra))

    assert finding.request.raw is None
    assert finding.request.body is None


def test_request_cookie_header_is_parsed_into_cookies_dict():
    extra = (
        "<requestresponse>"
        "<request method=\"GET\">GET /p HTTP/1.1\r\n"
        "Host: example.test\r\nCookie: session=abc123; theme=dark"
        "\r\n\r\n</request>"
        "</requestresponse>"
    )

    finding = first_finding(make_issue_xml(extra=extra))

    assert finding.request.cookies == {
        "session": "abc123",
        "theme": "dark",
    }


def test_response_set_cookie_header_is_parsed_into_cookies_dict():
    """
    _parse_cookies() splits every ';'-separated "name=value" segment
    of the Set-Cookie header as a cookie pair -- it does not recognize
    cookie attributes like Path/Domain/Secure. A "Path=/" attribute is
    therefore captured alongside the real cookie. This documents that
    actual behavior rather than an idealized RFC 6265 cookie parse.
    """

    extra = (
        "<requestresponse>"
        "<response>HTTP/1.1 200 OK\r\n"
        "Set-Cookie: session=xyz789; Path=/\r\n\r\nOK</response>"
        "</requestresponse>"
    )

    finding = first_finding(make_issue_xml(extra=extra))

    assert finding.response.cookies == {
        "session": "xyz789",
        "Path": "/",
    }


def test_response_with_unparseable_status_line_defaults_to_zero():
    extra = (
        "<requestresponse>"
        "<response>not a valid status line at all\r\n\r\nbody"
        "</response>"
        "</requestresponse>"
    )

    finding = first_finding(make_issue_xml(extra=extra))

    assert finding.response.status_code == 0


def test_request_target_url_from_request_line_overrides_host_path():
    """
    _build_url_from_request() prefers the request-line target over
    the <host>/<path> elements when the request line has a path.
    """

    extra = (
        "<requestresponse>"
        "<request method=\"GET\">GET /actual-target?x=1 HTTP/1.1\r\n"
        "Host: example.test\r\n\r\n</request>"
        "</requestresponse>"
    )

    finding = first_finding(
        make_issue_xml(host="example.test", path="/p", extra=extra)
    )

    assert finding.request.url == (
        "http://example.test/actual-target?x=1"
    )


def test_request_line_absolute_url_target_is_used_as_is():
    extra = (
        "<requestresponse>"
        "<request method=\"GET\">GET http://other.test/z HTTP/1.1"
        "\r\nHost: example.test\r\n\r\n</request>"
        "</requestresponse>"
    )

    finding = first_finding(make_issue_xml(extra=extra))

    assert finding.request.url == "http://other.test/z"


def test_host_without_scheme_defaults_to_http():
    finding = first_finding(
        make_issue_xml(host="example.test", path="/p")
    )

    assert finding.request.url == "http://example.test/p"


def test_host_with_explicit_https_scheme_is_preserved():
    finding = first_finding(
        make_issue_xml(host="https://secure.test", path="/p")
    )

    assert finding.request.url == "https://secure.test/p"


def test_query_parameter_detected_when_it_appears_in_location():
    extra = (
        "<requestresponse>"
        "<request method=\"GET\">GET /search?query=abc&amp;page=1 "
        "HTTP/1.1\r\nHost: example.test\r\n\r\n</request>"
        "</requestresponse>"
    )

    finding = first_finding(
        make_issue_xml(
            location="The value of request parameter query is copied",
            extra=extra,
        )
    )

    assert finding.target.parameter == "query"
    assert finding.target.parameter_location == "QUERY"


def test_extract_cwe_from_vulnerability_classifications_html():
    extra = (
        "<vulnerabilityClassifications>"
        "&lt;ul&gt;&lt;li&gt;&lt;a href=\"https://cwe.mitre.org/"
        "data/definitions/89.html\"&gt;CWE-89: SQL Injection&lt;/a&gt;"
        "&lt;/li&gt;&lt;/ul&gt;"
        "</vulnerabilityClassifications>"
    )

    finding = first_finding(make_issue_xml(extra=extra))

    assert finding.vulnerability.cwe == "CWE-89"


def test_extract_multiple_references():
    extra = (
        "<references>"
        "&lt;ul&gt;&lt;li&gt;&lt;a href=\"https://example.test/a\"&gt;"
        "A&lt;/a&gt;&lt;/li&gt;&lt;li&gt;&lt;a href=\"https://"
        "example.test/b\"&gt;B&lt;/a&gt;&lt;/li&gt;&lt;/ul&gt;"
        "</references>"
    )

    finding = first_finding(make_issue_xml(extra=extra))

    assert finding.references == [
        "https://example.test/a",
        "https://example.test/b",
    ]
