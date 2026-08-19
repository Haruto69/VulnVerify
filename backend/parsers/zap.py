import json
import logging
import re
from dataclasses import dataclass
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
from backend.parsers.zap_har import is_har_report, parse_har_report
from backend.verification.xss_context import XssSubtype


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ZapAlertClassification:
    """
    What one ZAP plugin ID means to VulnVerify: the NormalizedFinding
    category/subtype it produces, and the CWE to fall back to only
    when ZAP's own cweid is missing/unusable for that alert.

    Keeping category/subtype/cwe_fallback bundled per plugin ID (
    rather than three parallel dicts, or an if/elif chain hardcoding
    "SQLI") is what lets _build_normalized_finding stay a single,
    vulnerability-agnostic construction path -- adding a new
    supported ZAP plugin means adding one entry here, not touching
    the HTTP/request/response normalization logic at all.
    """

    category: str
    subtype: str | None
    cwe_fallback: str


class ZapParser(BaseParser):

    # Plugin IDs VulnVerify currently knows how to classify and
    # normalize. This is the single source of truth for
    # "is this ZAP alert supported" -- extend it (not an SQLi-only
    # allowlist plus scattered hardcoded category strings) to support
    # another ZAP plugin.
    PLUGIN_CLASSIFICATIONS: dict[str, ZapAlertClassification] = {
        "40018": ZapAlertClassification(
            category="SQLI",
            subtype=None,
            cwe_fallback="CWE-89",
        ),
        "40012": ZapAlertClassification(
            category="XSS",
            subtype=XssSubtype.REFLECTED.value,
            cwe_fallback="CWE-79",
        ),
    }

    # A small, exact-match (never substring) fallback from a known
    # ZAP alert/name string to its plugin ID, used only when
    # "pluginid" itself is missing or not one of the IDs above. This
    # exists so a minor ZAP version bump that stops sending pluginid,
    # or renames it, doesn't silently discard a genuinely-supported
    # alert -- it deliberately does NOT do fuzzy/substring matching
    # (e.g. "contains xss"), which would risk misclassifying an
    # unrelated alert whose description happens to mention another
    # vulnerability type in passing.
    ALERT_NAME_TO_PLUGIN_ID: dict[str, str] = {
        "sql injection": "40018",
        "cross site scripting (reflected)": "40012",
    }

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

        # HAR (log.entries[]) is a distinct export shape from ZAP's
        # own Traditional JSON alert report -- it carries raw
        # captured traffic with no scanner risk judgment at all, so
        # it is routed to a completely separate parsing path
        # (backend/parsers/zap_har.py) rather than being forced
        # through alert-shaped parsing. This check is unambiguous
        # (HAR's top-level shape is exclusively {"log": {...}} per
        # spec) and never guesses from file extension or content
        # substrings.
        if is_har_report(report):
            return parse_har_report(
                report=report,
                scan_id=scan_id,
            )

        return self._parse_traditional_alerts(
            report=report,
            scan_id=scan_id,
        )

    def _parse_traditional_alerts(
        self,
        report: dict,
        scan_id: str,
    ) -> list[NormalizedFinding]:
        """
        ZAP's "Traditional JSON Report" (alerts + instances) path.

        Unchanged from before HAR support was added -- byte-for-byte
        the same validation and construction logic, just moved into
        its own method so `parse()` can dispatch to it.
        """

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
            classification = self._classify_alert(alert)

            if classification is None:
                logger.debug(
                    "Skipping unsupported ZAP alert: pluginid=%s "
                    "name=%s",
                    alert.get("pluginid"),
                    alert.get("alert") or alert.get("name"),
                )
                continue

            findings.append(
                self._build_normalized_finding(
                    alert=alert,
                    instance=instance,
                    scan_id=scan_id,
                    scan_timestamp=scan_timestamp,
                    classification=classification,
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

    def _resolve_plugin_id(
        self,
        alert: dict,
    ) -> str | None:
        """
        Resolve the plugin ID that determines this alert's
        classification. pluginid is the primary signal; the
        exact-match alert-name fallback in ALERT_NAME_TO_PLUGIN_ID is
        only consulted when pluginid itself doesn't resolve to a
        supported plugin, and never via partial/substring text
        matches.
        """

        plugin_id = str(alert.get("pluginid", "")).strip()

        if plugin_id in self.PLUGIN_CLASSIFICATIONS:
            return plugin_id

        alert_name = (
            alert.get("alert") or alert.get("name") or ""
        ).strip().lower()

        return self.ALERT_NAME_TO_PLUGIN_ID.get(alert_name)

    def _classify_alert(
        self,
        alert: dict,
    ) -> ZapAlertClassification | None:
        """
        Resolve an alert to its ZapAlertClassification, or None when
        it is not (yet) a supported ZAP plugin.
        """

        plugin_id = self._resolve_plugin_id(alert)

        if plugin_id is None:
            return None

        return self.PLUGIN_CLASSIFICATIONS.get(plugin_id)

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
        classification: ZapAlertClassification,
    ) -> NormalizedFinding:

        plugin_id = self._resolve_plugin_id(alert)

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
            cwe = classification.cwe_fallback
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
                scanner_finding_id=plugin_id,
                original_name=(
                    alert.get("name")
                    or alert.get("alert")
                    or "Unknown ZAP finding"
                ),
            ),

            vulnerability=VulnerabilityInfo(
                category=classification.category,
                subtype=classification.subtype,

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
                "zap_description": alert.get("desc"),
                "zap_solution": alert.get("solution"),
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