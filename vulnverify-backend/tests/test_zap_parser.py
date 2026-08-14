import json

import pytest

from backend.parsers.zap import ZapParser


def test_valid_zap_report():
    with open("tests/fixtures/zap/zap_report.json", "rb") as file:
        content = file.read()

    parser = ZapParser()

    findings = parser.parse(
        content=content,
        scan_id="scan-test-zap"
    )

    assert findings == []


def test_invalid_json():
    parser = ZapParser()

    with pytest.raises(ValueError, match="Invalid ZAP JSON report"):
        parser.parse(
            content=b"this is not json",
            scan_id="scan-test-zap"
        )


def test_non_zap_json():
    parser = ZapParser()

    content = b'{"@programName": "NOT_ZAP", "site": []}'

    with pytest.raises(ValueError, match="not an OWASP ZAP report"):
        parser.parse(
            content=content,
            scan_id="scan-test-zap"
        )


def test_extracts_zap_alert_instances():
    with open("tests/fixtures/zap/zap_report.json", "rb") as file:
        content = file.read()

    parser = ZapParser()

    report = json.loads(content.decode("utf-8"))

    alert_instances = parser._extract_alert_instances(report)

    assert len(alert_instances) > 0

    alert, instance = alert_instances[0]

    assert "alert" in alert
    assert "pluginid" in alert

    assert "uri" in instance
    assert "method" in instance
    assert "request-header" in instance
    assert "response-header" in instance