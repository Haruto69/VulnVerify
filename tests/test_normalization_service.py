from backend.models.normalized_finding import NormalizedFinding
from backend.parsers.base import BaseParser
from backend.services.normalization_service import normalize_scan


class FakeParser(BaseParser):

    def parse(
        self,
        content: bytes,
        scan_id: str
    ) -> list[NormalizedFinding]:

        return [
            NormalizedFinding(
                scan_id=scan_id,
                finding_id="finding-test-001",

                source={
                    "scanner": "FAKE",
                    "scanner_finding_id": "fake-001",
                    "original_name": "Fake SQL Injection"
                },

                vulnerability={
                    "category": "SQLI",
                    "subtype": None,

                    "raw_severity": "High",
                    "normalized_severity": "HIGH",

                    "raw_confidence": "Medium",
                    "normalized_confidence": "MEDIUM",

                    "cwe": "CWE-89"
                },

                target={
                    "url": "http://localhost/test?id=1",
                    "normalized_url": "http://localhost/test",
                    "host": "localhost",
                    "path": "/test",

                    "parameter": "id",
                    "parameter_location": "QUERY"
                },

                original_test={
                    "payload": "1 OR 1=1",
                    "evidence": "Fake evidence"
                },

                request={
                    "method": "GET",
                    "url": "http://localhost/test?id=1",
                    "path": "/test",

                    "query_parameters": {
                        "id": ["1"]
                    },

                    "headers": {},
                    "cookies": {},

                    "body": None,
                    "content_type": None,
                    "raw": None
                },

                response=None,

                references=[],
                metadata={}
            )
        ]


def test_normalize_scan_uses_parser():
    parser = FakeParser()

    findings = normalize_scan(
        parser=parser,
        content=b"fake scanner report",
        scan_id="scan-test-001"
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.scan_id == "scan-test-001"
    assert finding.source.scanner == "FAKE"
    assert finding.vulnerability.category == "SQLI"