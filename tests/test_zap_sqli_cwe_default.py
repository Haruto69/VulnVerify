import json

from backend.parsers.zap import ZapParser


def make_report(
    *,
    cweid=None,
) -> bytes:
    alert = {
        "pluginid": "40018",
        "alertRef": "40018",
        "name": "SQL Injection",
        "riskcode": "3",
        "confidence": "2",
        "instances": [
            {
                "id": "1",
                "uri": (
                    "http://test.local/item?"
                    "id=attack"
                ),
                "method": "GET",
                "param": "id",
                "attack": "scanner-payload",
                "evidence": "scanner-evidence",
                "request-header": (
                    "GET http://test.local/item?id=attack HTTP/1.1\r\n"
                    "Host: test.local\r\n"
                    "\r\n"
                ),
                "request-body": "",
                "response-header": (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "\r\n"
                ),
                "response-body": "ok",
            }
        ],
    }

    if cweid is not None:
        alert["cweid"] = cweid

    report = {
        "@programName": "ZAP",
        "@version": "2.17.0",
        "created": "2026-08-16T00:00:00Z",
        "site": [
            {
                "@name": "http://test.local",
                "alerts": [alert],
            }
        ],
    }

    return json.dumps(report).encode("utf-8")


def test_missing_sqli_cwe_defaults_to_cwe_89():
    findings = ZapParser().parse(
        make_report(),
        scan_id="SCAN-1",
    )

    assert len(findings) == 1
    assert findings[0].vulnerability.cwe == "CWE-89"


def test_negative_one_sqli_cwe_defaults_to_cwe_89():
    findings = ZapParser().parse(
        make_report(cweid="-1"),
        scan_id="SCAN-1",
    )

    assert findings[0].vulnerability.cwe == "CWE-89"


def test_explicit_cwe_is_preserved():
    findings = ZapParser().parse(
        make_report(cweid="89"),
        scan_id="SCAN-1",
    )

    assert findings[0].vulnerability.cwe == "CWE-89"