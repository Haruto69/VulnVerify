"""
Focused CORS tests for local frontend integration.

Covers only the CORSMiddleware configuration added in backend/main.py.
No endpoint behavior, model, or verification logic is exercised here --
/health is used as a stable, side-effect-free target so these tests
stay independent of the application pipeline.

Note on semantics: for a simple (non-preflight) cross-origin request,
CORS is enforced by the *browser*, not the server. A disallowed origin
still receives a normal 200 response; what makes it "not granted CORS
access" is the absence of the Access-Control-Allow-Origin header.
Preflight OPTIONS requests are different -- Starlette rejects a
disallowed origin outright with 400.
"""

from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


ALLOWED_ORIGIN_LOCALHOST = "http://localhost:5173"
ALLOWED_ORIGIN_LOOPBACK_IP = "http://127.0.0.1:5173"
DISALLOWED_ORIGIN = "http://evil.example.com"


def test_allowed_localhost_origin_receives_allow_origin_header():
    response = client.get(
        "/health",
        headers={"Origin": ALLOWED_ORIGIN_LOCALHOST},
    )

    assert response.status_code == 200
    assert (
        response.headers["access-control-allow-origin"]
        == ALLOWED_ORIGIN_LOCALHOST
    )


def test_allowed_loopback_ip_origin_receives_allow_origin_header():
    response = client.get(
        "/health",
        headers={"Origin": ALLOWED_ORIGIN_LOOPBACK_IP},
    )

    assert response.status_code == 200
    assert (
        response.headers["access-control-allow-origin"]
        == ALLOWED_ORIGIN_LOOPBACK_IP
    )


def test_disallowed_origin_is_not_granted_cors_access():
    response = client.get(
        "/health",
        headers={"Origin": DISALLOWED_ORIGIN},
    )

    # The server still answers normally; the browser is what blocks the
    # response. What matters is that no allow-origin grant is issued.
    assert "access-control-allow-origin" not in response.headers


def test_preflight_from_allowed_origin_succeeds_with_cors_headers():
    response = client.options(
        "/api/v1/scans",
        headers={
            "Origin": ALLOWED_ORIGIN_LOCALHOST,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200

    assert (
        response.headers["access-control-allow-origin"]
        == ALLOWED_ORIGIN_LOCALHOST
    )

    allowed_methods = response.headers[
        "access-control-allow-methods"
    ]

    for method in ("GET", "POST", "OPTIONS"):
        assert method in allowed_methods

    assert (
        "content-type"
        in response.headers[
            "access-control-allow-headers"
        ].lower()
    )


def test_preflight_from_disallowed_origin_is_rejected():
    response = client.options(
        "/api/v1/scans",
        headers={
            "Origin": DISALLOWED_ORIGIN,
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_request_without_origin_header_is_unaffected():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "access-control-allow-origin" not in response.headers
