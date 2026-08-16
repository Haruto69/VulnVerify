import json
import re
from urllib.parse import parse_qs, urlsplit, urlunsplit
from uuid import uuid4

from backend.models.normalized_finding import (
    FindingContext,
    FindingSource,
    HttpRequest,
    HttpResponse,
    NormalizedFinding,
    OriginalTest,
    ParameterLocation,
    RequirementState,
    TargetInfo,
    VulnerabilityInfo,
)
from backend.parsers.base import BaseParser


class ZapParser(BaseParser):

    SQLI_PLUGIN_IDS = {"40018"}

    RISK_CODE_MAP = {
        "0": "INFORMATIONAL",
        "1": "LOW",
        "2": "MEDIUM",
        "3": "HIGH",
        "4": "CRITICAL",
    }

    def parse(
        self,
        content: bytes,
        scan_id: str
    ) -> list[NormalizedFinding]:

        try:
            report = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid ZAP JSON report") from exc

        if report.get("@programName") != "ZAP":
            raise ValueError("JSON report is not an OWASP ZAP report")

        sites = report.get("site")

        if not isinstance(sites, list):
            raise ValueError(
                "ZAP report does not contain a valid site list"
            )

        alert_instances = self._extract_alert_instances(report)
        scan_timestamp = self._extract_scan_timestamp(report)

        findings = []

        for alert, instance in alert_instances:
            if not self._is_supported_alert(alert):
                continue

            findings.append(
                self._build_normalized_finding(
                    alert=alert,
                    instance=instance,
                    scan_id=scan_id,
                    scan_timestamp=scan_timestamp,
                )
            )

        return findings

    def _extract_alert_instances(
        self,
        report: dict
    ) -> list[tuple[dict, dict]]:

        alert_instances = []

        for site in report["site"]:
            alerts = site.get("alerts", [])

            if not isinstance(alerts, list):
                raise ValueError(
                    "Invalid alerts structure in ZAP report"
                )

            for alert in alerts:
                instances = alert.get("instances", [])

                if not isinstance(instances, list):
                    raise ValueError(
                        "Invalid instances structure in ZAP alert"
                    )

                for instance in instances:
                    alert_instances.append(
                        (alert, instance)
                    )

        return alert_instances

    def _is_supported_alert(
        self,
        alert: dict
    ) -> bool:

        return str(alert.get("pluginid", "")) in self.SQLI_PLUGIN_IDS

    def _extract_scan_timestamp(
        self,
        report: dict
    ) -> str | None:

        return (
            report.get("created")
            or report.get("@generated")
        )

    def _build_normalized_finding(
        self,
        alert: dict,
        instance: dict,
        scan_id: str,
        scan_timestamp: str | None,
    ) -> NormalizedFinding:

        url = instance.get("uri", "")
        parsed_url = urlsplit(url)

        parameter = instance.get("param") or None

        query_parameters = parse_qs(
            parsed_url.query,
            keep_blank_values=True
        )

        parameter_location = self._detect_parameter_location(
            parameter=parameter,
            query_parameters=query_parameters,
        )

        request_raw = instance.get("request-header", "")
        request_headers = self._parse_request_headers(request_raw)
        request_cookies = self._parse_cookie_header(
            request_headers.get("cookie")
        )

        response_raw = instance.get("response-header", "")
        response_status = self._parse_response_status(response_raw)
        response_headers = self._parse_response_headers(response_raw)

        normalized_url = urlunsplit(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                "",
                "",
            )
        )

        risk_code = str(alert.get("riskcode", ""))
        normalized_severity = self.RISK_CODE_MAP.get(
            risk_code,
            "UNKNOWN"
        )

        cwe_id = str(alert.get("cweid", "")).strip()

        if not cwe_id or cwe_id == "-1":
            cwe = "CWE-89"
        else:
            cwe = f"CWE-{cwe_id}"

        references = self._extract_references(
            alert.get("reference", "")
        )

        return NormalizedFinding(
            scan_id=scan_id,
            finding_id=str(uuid4()),

            source=FindingSource(
                scanner="ZAP",
                scanner_finding_id=str(
                    alert.get("pluginid")
                ),
                original_name=(
                    alert.get("name")
                    or alert.get("alert")
                    or "Unknown ZAP finding"
                ),
            ),

            vulnerability=VulnerabilityInfo(
                category="SQLI",
                subtype=None,

                raw_severity=(
                    alert.get("riskdesc")
                    or risk_code
                    or "Unknown"
                ),

                normalized_severity=normalized_severity,

                raw_confidence=str(
                    alert.get("confidence", "")
                ) or None,

                normalized_confidence="UNKNOWN",

                cwe=cwe,
            ),

            target=TargetInfo(
                url=url,
                normalized_url=normalized_url,
                host=parsed_url.hostname or "",
                path=parsed_url.path or "/",
                parameter=parameter,
                parameter_location=parameter_location,
            ),

            original_test=OriginalTest(
                payload=instance.get("attack") or None,
                evidence=instance.get("evidence") or None,
            ),

            request=HttpRequest(
                method=instance.get("method", "GET"),
                url=url,
                path=parsed_url.path or "/",
                query_parameters=query_parameters,
                headers=request_headers,
                cookies=request_cookies,
                body=instance.get("request-body") or None,
                content_type=request_headers.get(
                    "content-type"
                ),
                raw=self._combine_http_message(
                    instance.get("request-header", ""),
                    instance.get("request-body", ""),
                ),
            ),

            response=HttpResponse(
                status_code=response_status,
                headers=response_headers,
                cookies={},
                body=instance.get("response-body") or None,
                raw=self._combine_http_message(
                    instance.get("response-header", ""),
                    instance.get("response-body", ""),
                ),
                response_time_ms=None,
            ),

            context=FindingContext(
                authentication_required=RequirementState.UNKNOWN,
                session_required=RequirementState.UNKNOWN,
            ),

            references=references,

            metadata={
                "scan_timestamp": scan_timestamp,
                "zap_alert_ref": alert.get("alertRef"),
                "zap_instance_id": instance.get("id"),
                "zap_source_id": alert.get("sourceid"),
                "zap_wasc_id": alert.get("wascid"),
                "zap_other_info": instance.get("otherinfo"),
                "zap_alert_other_info": alert.get("otherinfo"),
                "zap_tags": alert.get("tags", []),
            },
        )

    def _detect_parameter_location(
        self,
        parameter: str | None,
        query_parameters: dict[str, list[str]]
    ) -> ParameterLocation:

        if (
            parameter
            and parameter in query_parameters
        ):
            return ParameterLocation.QUERY

        return ParameterLocation.UNKNOWN

    def _parse_request_headers(
        self,
        raw_headers: str
    ) -> dict[str, str]:

        return self._parse_headers(
            raw_headers=raw_headers,
            skip_first_line=True,
        )

    def _parse_response_headers(
        self,
        raw_headers: str
    ) -> dict[str, str]:

        return self._parse_headers(
            raw_headers=raw_headers,
            skip_first_line=True,
        )

    def _parse_headers(
        self,
        raw_headers: str,
        skip_first_line: bool
    ) -> dict[str, str]:

        if not raw_headers:
            return {}

        lines = raw_headers.splitlines()

        if skip_first_line and lines:
            lines = lines[1:]

        headers = {}

        for line in lines:
            if not line.strip():
                continue

            if ":" not in line:
                continue

            name, value = line.split(":", 1)

            headers[
                name.strip().lower()
            ] = value.strip()

        return headers

    def _parse_cookie_header(
        self,
        cookie_header: str | None
    ) -> dict[str, str]:

        if not cookie_header:
            return {}

        cookies = {}

        for item in cookie_header.split(";"):
            item = item.strip()

            if "=" not in item:
                continue

            name, value = item.split("=", 1)

            cookies[
                name.strip()
            ] = value.strip()

        return cookies

    def _parse_response_status(
        self,
        raw_headers: str
    ) -> int:

        if not raw_headers:
            return 0

        first_line = raw_headers.splitlines()[0]

        parts = first_line.split()

        if len(parts) < 2:
            return 0

        try:
            return int(parts[1])
        except ValueError:
            return 0

    def _extract_references(
        self,
        raw_reference: str
    ) -> list[str]:

        if not raw_reference:
            return []

        return re.findall(
            r"https?://[^<\s]+",
            raw_reference
        )

    def _combine_http_message(
        self,
        headers: str,
        body: str
    ) -> str | None:

        if not headers and not body:
            return None

        return f"{headers}{body}"