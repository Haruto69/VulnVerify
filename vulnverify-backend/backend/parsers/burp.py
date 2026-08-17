import base64
import html
import re
import xml.etree.ElementTree as ET
from urllib.parse import parse_qs, urlsplit, urlunsplit
from uuid import uuid4

from backend.models.normalized_finding import (
    FindingContext,
    FindingSource,
    HttpRequest,
    HttpResponse,
    NormalizedFinding,
    NormalizedSeverity,
    NormalizedConfidence,
    OriginalTest,
    ParameterLocation,
    RequirementState,
    TargetInfo,
    VulnerabilityInfo,
    VulnerabilityCategory,
)
from backend.parsers.base import BaseParser


class BurpParser(BaseParser):

    SEVERITY_MAP = {
        "information": NormalizedSeverity.INFORMATIONAL,
        "informational": NormalizedSeverity.INFORMATIONAL,
        "low": NormalizedSeverity.LOW,
        "medium": NormalizedSeverity.MEDIUM,
        "high": NormalizedSeverity.HIGH,
        "critical": NormalizedSeverity.CRITICAL,
    }

    CONFIDENCE_MAP = {
        "tentative": NormalizedConfidence.LOW,
        "firm": NormalizedConfidence.MEDIUM,
        "certain": NormalizedConfidence.HIGH,
    }

    # ---------------------------------------------------------
    # XML helpers
    # ---------------------------------------------------------

    @staticmethod
    def _local_name(element: ET.Element) -> str:
        """
        Return the XML tag name without a namespace.

        Handles both:

            <issue>
            <burp:issue>
            <{namespace}issue>
        """
        return element.tag.rsplit("}", 1)[-1].lower()

    def _find_child(
        self,
        element: ET.Element,
        name: str,
    ) -> ET.Element | None:
        """
        Find a direct child while ignoring XML namespaces.
        """
        wanted = name.lower()

        for child in list(element):
            if self._local_name(child) == wanted:
                return child

        return None

    def _find_text(
        self,
        element: ET.Element,
        path: str,
        default: str | None = None,
    ) -> str | None:
        """
        Namespace-independent replacement for findtext().
        """

        current = element

        for part in path.split("/"):
            if not part:
                continue

            current = self._find_child(
                current,
                part,
            )

            if current is None:
                return default

        return (
            current.text
            if current.text is not None
            else default
        )

    def _find_element(
        self,
        element: ET.Element,
        path: str,
    ) -> ET.Element | None:
        """
        Namespace-independent nested element lookup.
        """

        current = element

        for part in path.split("/"):
            if not part:
                continue

            current = self._find_child(
                current,
                part,
            )

            if current is None:
                return None

        return current

    def _find_all_by_local_name(
        self,
        root: ET.Element,
        name: str,
    ) -> list[ET.Element]:
        """
        Find ALL elements with a particular local XML name,
        regardless of namespace.
        """

        wanted = name.lower()

        return [
            element
            for element in root.iter()
            if self._local_name(element) == wanted
        ]

    # ---------------------------------------------------------
    # Main parser
    # ---------------------------------------------------------

    def parse(
        self,
        content: bytes,
        scan_id: str,
    ) -> list[NormalizedFinding]:

        try:
            root = ET.fromstring(content)

        except ET.ParseError as exc:
            raise ValueError(
                "Invalid Burp XML report"
            ) from exc

        root_name = self._local_name(root)

        # Burp XML exports normally use <issues>.
        #
        # Some exports may use a different root while still
        # containing Burp <issue> elements, so we primarily
        # validate based on the actual issue elements.
        if root_name not in {
            "issues",
            "burp",
        }:
            issue_elements = (
                self._find_all_by_local_name(
                    root,
                    "issue",
                )
            )

            if not issue_elements:
                raise ValueError(
                    "XML report is not a Burp report"
                )
        else:
            issue_elements = (
                self._find_all_by_local_name(
                    root,
                    "issue",
                )
            )

        findings: list[NormalizedFinding] = []

        # IMPORTANT:
        #
        # Do not deduplicate here.
        #
        # Every Burp <issue> becomes one normalized finding.
        #
        # If Burp reports 53 issues, this loop must produce
        # 53 normalized findings.
        for issue in issue_elements:

            name = (
                self._find_text(
                    issue,
                    "name",
                )
                or "Unknown Burp finding"
            )

            category = self._map_category(
                name
            )

            findings.append(
                self._build_finding(
                    issue=issue,
                    scan_id=scan_id,
                    category=category,
                )
            )

        return findings

    # ---------------------------------------------------------
    # Build normalized finding
    # ---------------------------------------------------------

    def _build_finding(
        self,
        issue: ET.Element,
        scan_id: str,
        category: VulnerabilityCategory,
    ) -> NormalizedFinding:

        name = (
            self._find_text(
                issue,
                "name",
            )
            or "Unknown Burp finding"
        )

        issue_type = (
            self._find_text(
                issue,
                "type",
            )
            or ""
        )

        host = (
            self._find_text(
                issue,
                "host",
            )
            or ""
        )

        path = (
            self._find_text(
                issue,
                "path",
            )
            or "/"
        )

        location = (
            self._find_text(
                issue,
                "location",
            )
            or ""
        )

        raw_severity = (
            self._find_text(
                issue,
                "severity",
            )
            or "Unknown"
        )

        raw_confidence = self._find_text(
            issue,
            "confidence",
        )

        # Build HTTP request.
        request = self._build_request(
            issue=issue,
            host=host,
            path=path,
        )

        # Build HTTP response.
        response = self._build_response(
            issue
        )

        # Prefer URL from request.
        url = (
            request.url
            or self._build_url(
                host,
                path,
            )
        )

        parsed_url = urlsplit(url)

        # CWE.
        cwe = self._extract_cwe(
            self._find_text(
                issue,
                "vulnerabilityClassifications",
            )
            or ""
        )

        # References.
        references = self._extract_references(
            self._find_text(
                issue,
                "references",
            )
            or ""
        )

        # Severity.
        normalized_severity = (
            self.SEVERITY_MAP.get(
                raw_severity.strip().lower(),
                NormalizedSeverity.UNKNOWN,
            )
        )

        # Confidence.
        normalized_confidence = (
            self.CONFIDENCE_MAP.get(
                (raw_confidence or "")
                .strip()
                .lower(),
                NormalizedConfidence.UNKNOWN,
            )
        )

        # Parameter.
        parameter, parameter_location = (
            self._extract_parameter(
                location=location,
                url=url,
            )
        )

        return NormalizedFinding(
            scan_id=scan_id,

            finding_id=str(uuid4()),

            source=FindingSource(
                scanner="Burp",

                scanner_finding_id=(
                    self._find_text(
                        issue,
                        "serialNumber",
                    )
                ),

                original_name=name,
            ),

            vulnerability=VulnerabilityInfo(
                category=category,

                subtype=name,

                raw_severity=raw_severity,

                normalized_severity=(
                    normalized_severity
                ),

                raw_confidence=raw_confidence,

                normalized_confidence=(
                    normalized_confidence
                ),

                cwe=cwe,
            ),

            target=TargetInfo(
                url=url,

                normalized_url=urlunsplit(
                    (
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path or "/",
                        "",
                        "",
                    )
                ),

                host=(
                    parsed_url.hostname
                    or host
                ),

                path=(
                    parsed_url.path
                    or path
                    or "/"
                ),

                parameter=parameter,

                parameter_location=(
                    parameter_location
                ),
            ),

            original_test=OriginalTest(
                payload=None,

                evidence=self._clean_html(
                    self._find_text(
                        issue,
                        "issueDetail",
                    )
                    or ""
                ),
            ),

            request=request,

            response=response,

            context=FindingContext(
                authentication_required=(
                    RequirementState.UNKNOWN
                ),

                session_required=(
                    RequirementState.UNKNOWN
                ),
            ),

            references=references,

            metadata={
                "burp_type": issue_type,

                "burp_location": location,

                "burp_issue_background": (
                    self._find_text(
                        issue,
                        "issueBackground",
                    )
                ),

                "burp_remediation_background": (
                    self._find_text(
                        issue,
                        "remediationBackground",
                    )
                ),

                "burp_response_redirected": (
                    self._find_text(
                        issue,
                        "requestresponse/"
                        "responseRedirected",
                    )
                ),
            },
        )

    # ---------------------------------------------------------
    # HTTP request
    # ---------------------------------------------------------

    def _build_request(
        self,
        issue: ET.Element,
        host: str,
        path: str,
    ) -> HttpRequest:

        request_element = self._find_element(
            issue,
            "requestresponse/request",
        )

        # No request available.
        if request_element is None:

            url = self._build_url(
                host,
                path,
            )

            return HttpRequest(
                method="GET",
                url=url,
                path=path or "/",
            )

        raw = self._decode_message(
            request_element
        )

        method = (
            request_element.get(
                "method",
                "GET",
            )
        )

        headers, body = (
            self._split_http_message(
                raw
            )
        )

        url = self._build_url_from_request(
            host=host,
            path=path,
            headers=headers,
        )

        parsed_url = urlsplit(url)

        query_parameters = parse_qs(
            parsed_url.query,
            keep_blank_values=True,
        )

        request_headers = (
            self._parse_headers(
                headers
            )
        )

        cookies = self._parse_cookies(
            request_headers.get("cookie")
        )

        return HttpRequest(
            method=method,

            url=url,

            path=(
                parsed_url.path
                or "/"
            ),

            query_parameters=(
                query_parameters
            ),

            headers=request_headers,

            cookies=cookies,

            body=body or None,

            content_type=(
                request_headers.get(
                    "content-type"
                )
            ),

            raw=raw or None,
        )

    # ---------------------------------------------------------
    # HTTP response
    # ---------------------------------------------------------

    def _build_response(
        self,
        issue: ET.Element,
    ) -> HttpResponse | None:

        response_element = self._find_element(
            issue,
            "requestresponse/response",
        )

        if response_element is None:
            return None

        raw = self._decode_message(
            response_element
        )

        headers, body = (
            self._split_http_message(
                raw
            )
        )

        status_code = (
            self._parse_status_code(
                headers
            )
        )

        response_headers = (
            self._parse_headers(
                headers
            )
        )

        return HttpResponse(
            status_code=status_code,

            headers=response_headers,

            cookies=self._parse_cookies(
                response_headers.get(
                    "set-cookie"
                )
            ),

            body=body or None,

            raw=raw or None,

            response_time_ms=None,
        )

    # ---------------------------------------------------------
    # Burp message decoding
    # ---------------------------------------------------------

    def _decode_message(
        self,
        element: ET.Element,
    ) -> str:

        value = element.text or ""

        if element.get("base64") == "true":

            try:
                return (
                    base64.b64decode(
                        value
                    )
                    .decode(
                        "utf-8",
                        errors="replace",
                    )
                )

            except (
                ValueError,
                UnicodeDecodeError,
            ):
                return ""

        return value

    # ---------------------------------------------------------
    # HTTP parsing
    # ---------------------------------------------------------

    def _split_http_message(
        self,
        raw: str,
    ) -> tuple[str, str]:

        if "\r\n\r\n" in raw:

            return raw.split(
                "\r\n\r\n",
                1,
            )

        if "\n\n" in raw:

            return raw.split(
                "\n\n",
                1,
            )

        return raw, ""

    def _parse_headers(
        self,
        raw_headers: str,
    ) -> dict[str, str]:

        if not raw_headers:
            return {}

        lines = raw_headers.splitlines()

        if lines:
            lines = lines[1:]

        headers: dict[str, str] = {}

        for line in lines:

            if ":" not in line:
                continue

            name, value = line.split(
                ":",
                1,
            )

            headers[
                name.strip().lower()
            ] = value.strip()

        return headers

    def _parse_cookies(
        self,
        cookie_header: str | None,
    ) -> dict[str, str]:

        if not cookie_header:
            return {}

        cookies: dict[str, str] = {}

        for item in cookie_header.split(";"):

            item = item.strip()

            if "=" not in item:
                continue

            name, value = item.split(
                "=",
                1,
            )

            cookies[
                name.strip()
            ] = value.strip()

        return cookies

    def _parse_status_code(
        self,
        raw_headers: str,
    ) -> int:

        if not raw_headers:
            return 0

        lines = raw_headers.splitlines()

        if not lines:
            return 0

        parts = lines[0].split()

        if len(parts) < 2:
            return 0

        try:
            return int(parts[1])

        except ValueError:
            return 0

    # ---------------------------------------------------------
    # URL handling
    # ---------------------------------------------------------

    def _build_url(
        self,
        host: str,
        path: str,
    ) -> str:

        if (
            host.startswith("http://")
            or host.startswith("https://")
        ):

            return (
                host.rstrip("/")
                + "/"
                + path.lstrip("/")
            )

        return (
            "http://"
            + host.rstrip("/")
            + "/"
            + path.lstrip("/")
        )

    def _build_url_from_request(
        self,
        host: str,
        path: str,
        headers: str,
    ) -> str:

        request_lines = (
            headers.splitlines()
        )

        if request_lines:

            request_line = (
                request_lines[0]
            )

            parts = request_line.split()

            if len(parts) >= 2:

                request_target = parts[1]

                if (
                    request_target.startswith(
                        "http://"
                    )
                    or request_target.startswith(
                        "https://"
                    )
                ):

                    return request_target

                if request_target.startswith(
                    "/"
                ):

                    return self._build_url(
                        host,
                        request_target,
                    )

        return self._build_url(
            host,
            path,
        )

    # ---------------------------------------------------------
    # CWE
    # ---------------------------------------------------------

    def _extract_cwe(
        self,
        raw: str,
    ) -> str | None:

        decoded = html.unescape(raw)

        match = re.search(
            r"CWE-(\d+)",
            decoded,
            re.IGNORECASE,
        )

        if not match:
            return None

        return (
            f"CWE-{match.group(1)}"
        )

    # ---------------------------------------------------------
    # References
    # ---------------------------------------------------------

    def _extract_references(
        self,
        raw: str,
    ) -> list[str]:

        if not raw:
            return []

        decoded = html.unescape(raw)

        return re.findall(
            r"https?://[^\"'<>\s]+",
            decoded,
        )

    # ---------------------------------------------------------
    # HTML cleanup
    # ---------------------------------------------------------

    def _clean_html(
        self,
        value: str,
    ) -> str | None:

        if not value:
            return None

        value = html.unescape(
            value
        )

        value = re.sub(
            r"<[^>]+>",
            " ",
            value,
        )

        value = re.sub(
            r"\s+",
            " ",
            value,
        )

        return (
            value.strip()
            or None
        )

    # ---------------------------------------------------------
    # Parameter extraction
    # ---------------------------------------------------------

    def _extract_parameter(
        self,
        location: str,
        url: str,
    ) -> tuple[
        str | None,
        ParameterLocation,
    ]:

        if not location:

            return (
                None,
                ParameterLocation.UNKNOWN,
            )

        parsed = urlsplit(url)

        query_parameters = parse_qs(
            parsed.query,
            keep_blank_values=True,
        )

        for parameter in query_parameters:

            if parameter in location:

                return (
                    parameter,
                    ParameterLocation.QUERY,
                )

        return (
            None,
            ParameterLocation.UNKNOWN,
        )

    # ---------------------------------------------------------
    # Category mapping
    # ---------------------------------------------------------

    def _map_category(
        self,
        name: str,
    ) -> VulnerabilityCategory:

        lowered = (
            name.lower().strip()
        )

        # SQL Injection
        if (
            "sql injection" in lowered
            or "sql-injection" in lowered
        ):
            return (
                VulnerabilityCategory.SQLI
            )

        # CSRF
        if (
            "cross-site request forgery"
            in lowered
            or "csrf" in lowered
        ):
            return (
                VulnerabilityCategory.CSRF
            )

        # XSS
        if (
            "cross-site scripting"
            in lowered
            or "xss" in lowered
        ):
            return (
                VulnerabilityCategory.XSS
            )

        # CORS
        #
        # VulnerabilityCategory (frozen, backend/models/
        # normalized_finding.py) only defines SQLI, CSRF, XSS.
        # CORS, Information Disclosure, Security Misconfiguration,
        # Informational, and any unrecognized issue name have no
        # matching member, so they fall back to XSS rather than
        # crashing the parser.
        if (
            "cross-origin resource sharing"
            in lowered
            or "cors" in lowered
        ):
            return (
                VulnerabilityCategory.XSS
            )

        # Information Disclosure
        if (
            "private ip addresses disclosed"
            in lowered
            or "information disclosure"
            in lowered
            or "information leak"
            in lowered
        ):
            return (
                VulnerabilityCategory.XSS
            )

        # Security Misconfiguration
        if (
            "unencrypted communications"
            in lowered
            or "path-relative style sheet import"
            in lowered
            or "html does not specify charset"
            in lowered
        ):
            return (
                VulnerabilityCategory.XSS
            )

        # Informational
        if (
            "robots.txt file"
            in lowered
            or "openapi definition found"
            in lowered
            or "openapi definition"
            in lowered
        ):
            return (
                VulnerabilityCategory.XSS
            )

        # Unknown / unrecognized issue name
        return (
            VulnerabilityCategory.XSS
        )