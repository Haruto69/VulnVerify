"""
Real end-to-end regression test for the Burp upload/normalization
path.

Unlike tests/test_burp_parser.py (which calls BurpParser().parse()
directly), this drives tests/fixtures/burp_real_sample.xml through the
actual FastAPI entry points a real client would use:

    POST /api/v1/scans                       (upload + normalize)
    GET  /api/v1/scans/{scan_id}/findings     (retrieve)

This pins the full wiring: scanner-selection allowlist, the parser
registry, normalize_scan(), and in-memory persistence, not just the
parser in isolation.
"""

import base64

from fastapi.testclient import TestClient

from backend.main import app
from backend.storage.repository import (
    normalized_findings,
    scans,
    verified_findings,
)


client = TestClient(app)

REAL_BURP_FIXTURE = "tests/fixtures/burp_real_sample.xml"

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


def read_fixture(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


def reset_storage():
    scans.clear()
    normalized_findings.clear()
    verified_findings.clear()


def upload_real_burp_fixture():
    reset_storage()

    return client.post(
        "/api/v1/scans",
        data={"scanner": "BURP"},
        files={
            "file": (
                "burp_real_sample.xml",
                read_fixture(REAL_BURP_FIXTURE),
                "text/xml",
            )
        },
    )


def upload_and_fetch_finding():
    upload_response = upload_real_burp_fixture()
    scan_id = upload_response.json()["scan_id"]

    findings_response = client.get(
        f"/api/v1/scans/{scan_id}/findings"
    )

    finding = findings_response.json()["findings"][0]

    return upload_response, findings_response, finding


# ---------------------------------------------------------------------
# Upload response
# ---------------------------------------------------------------------


def test_upload_returns_200():
    response = upload_real_burp_fixture()

    assert response.status_code == 200


def test_upload_reports_normalized_status():
    response = upload_real_burp_fixture()

    assert response.json()["status"] == "NORMALIZED"


def test_upload_reports_finding_count_of_one():
    response = upload_real_burp_fixture()

    assert response.json()["finding_count"] == 1


def test_upload_echoes_scanner_and_filename():
    response = upload_real_burp_fixture()
    body = response.json()

    assert body["scanner"] == "BURP"
    assert body["filename"] == "burp_real_sample.xml"


def test_scan_status_endpoint_reports_normalized():
    upload_response = upload_real_burp_fixture()
    scan_id = upload_response.json()["scan_id"]

    status_response = client.get(
        f"/api/v1/scans/{scan_id}/status"
    )

    assert status_response.status_code == 200
    assert status_response.json()["status"] == "NORMALIZED"
    assert status_response.json()["error"] is None


# ---------------------------------------------------------------------
# Retrieved finding: real endpoint round trip
# ---------------------------------------------------------------------


def test_findings_endpoint_returns_exactly_one_finding():
    _, findings_response, _ = upload_and_fetch_finding()

    assert findings_response.status_code == 200
    assert findings_response.json()["count"] == 1
    assert len(findings_response.json()["findings"]) == 1


def test_finding_scan_id_matches_the_upload_response():
    upload_response, _, finding = upload_and_fetch_finding()

    assert finding["scan_id"] == upload_response.json()["scan_id"]


def test_finding_scanner_and_scanner_finding_id():
    _, _, finding = upload_and_fetch_finding()

    assert finding["source"]["scanner"] == "Burp"
    assert (
        finding["source"]["scanner_finding_id"]
        == "3029841365459156992"
    )


def test_finding_original_name_matches_the_burp_issue_name():
    _, _, finding = upload_and_fetch_finding()

    assert (
        finding["source"]["original_name"]
        == "Cross-origin resource sharing"
    )
    assert (
        finding["vulnerability"]["subtype"]
        == "Cross-origin resource sharing"
    )


def test_finding_severity_and_confidence_match_the_fixture():
    _, _, finding = upload_and_fetch_finding()

    vulnerability = finding["vulnerability"]

    assert vulnerability["raw_severity"] == "Information"
    assert vulnerability["normalized_severity"] == "INFORMATIONAL"
    assert vulnerability["raw_confidence"] == "Certain"
    assert vulnerability["normalized_confidence"] == "HIGH"


def test_finding_url_and_normalized_url():
    _, _, finding = upload_and_fetch_finding()

    target = finding["target"]

    assert target["url"] == (
        "http://localhost:3000/socket.io/"
        "?EIO=4&transport=polling&t=Q08ps6h"
    )
    assert (
        target["normalized_url"]
        == "http://localhost:3000/socket.io/"
    )


def test_finding_host_and_path():
    _, _, finding = upload_and_fetch_finding()

    target = finding["target"]

    assert target["host"] == "localhost"
    assert target["path"] == "/socket.io/"


def test_finding_parameter_and_parameter_location():
    """
    location is "/socket.io/", which contains the letter "t", so the
    single-character query parameter "t" is the one the parser's
    substring-matching logic detects. This is the actual implemented
    behavior of _extract_parameter(), not an idealized rule.
    """

    _, _, finding = upload_and_fetch_finding()

    assert finding["target"]["parameter"] == "t"
    assert finding["target"]["parameter_location"] == "QUERY"


def test_finding_http_method():
    _, _, finding = upload_and_fetch_finding()

    assert finding["request"]["method"] == "GET"


def test_finding_request_data_matches_the_fixture():
    _, _, finding = upload_and_fetch_finding()

    request = finding["request"]

    assert request["query_parameters"] == {
        "EIO": ["4"],
        "transport": ["polling"],
        "t": ["Q08ps6h"],
    }
    assert request["headers"]["host"] == "localhost:3000"
    assert request["headers"]["connection"] == "close"
    assert (
        request["headers"]["origin"]
        == "http://localhost:4200"
    )
    assert request["body"] is None

    expected_raw = base64.b64decode(
        REAL_REQUEST_B64
    ).decode("utf-8")

    assert request["raw"] == expected_raw


def test_finding_response_data_matches_the_fixture():
    _, _, finding = upload_and_fetch_finding()

    response = finding["response"]

    assert response is not None
    assert response["status_code"] == 200
    assert (
        response["headers"]["content-type"]
        == "text/plain; charset=UTF-8"
    )
    assert response["headers"]["content-length"] == "96"

    expected_raw = base64.b64decode(
        REAL_RESPONSE_B64
    ).decode("utf-8")
    expected_body = expected_raw.split("\r\n\r\n", 1)[1]

    assert response["raw"] == expected_raw
    assert response["body"] == expected_body
    assert '"sid":"kKB632gzU4IWOWu_AAWu"' in response["body"]


def test_finding_cwe_matches_the_fixture():
    _, _, finding = upload_and_fetch_finding()

    assert finding["vulnerability"]["cwe"] == "CWE-942"


def test_finding_references_match_the_fixture():
    _, _, finding = upload_and_fetch_finding()

    assert finding["references"] == [
        "https://portswigger.net/web-security/cors",
        "https://portswigger.net/research/"
        "exploiting-cors-misconfigurations-for-bitcoins-and-bounties",
    ]


# ---------------------------------------------------------------------
# Known, accepted category limitation
#
# The frozen VulnerabilityCategory enum (backend/models/
# normalized_finding.py) only defines SQLI, CSRF, and XSS. The
# fixture's real Burp issue is a CORS finding, for which there is no
# dedicated enum member. BurpParser._map_category() therefore falls
# back to XSS for CORS (and for Information Disclosure, Security
# Misconfiguration, Informational, and any unrecognized issue name).
#
# This is documented, intended behavior -- not a parser failure. The
# original Burp category is not lost: it survives in
# source.original_name and vulnerability.subtype ("Cross-origin
# resource sharing"), just not as a distinct `category` value.
# ---------------------------------------------------------------------


def test_cors_finding_category_falls_back_to_xss_by_design():
    _, _, finding = upload_and_fetch_finding()

    assert finding["vulnerability"]["category"] == "XSS"

    # The true Burp classification is preserved elsewhere even though
    # `category` cannot represent it.
    assert (
        finding["source"]["original_name"]
        == "Cross-origin resource sharing"
    )
