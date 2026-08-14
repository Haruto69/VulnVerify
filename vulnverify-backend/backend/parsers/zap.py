import json

from backend.models.normalized_finding import NormalizedFinding
from backend.parsers.base import BaseParser


class ZapParser(BaseParser):

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
            raise ValueError("ZAP report does not contain a valid site list")

        alert_instances = self._extract_alert_instances(report)

        return []

    def _extract_alert_instances(
        self,
        report: dict
    ) -> list[tuple[dict, dict]]:

        alert_instances = []

        for site in report["site"]:
            alerts = site.get("alerts", [])

            if not isinstance(alerts, list):
                raise ValueError("Invalid alerts structure in ZAP report")

            for alert in alerts:
                instances = alert.get("instances", [])

                if not isinstance(instances, list):
                    raise ValueError("Invalid instances structure in ZAP alert")

                for instance in instances:
                    alert_instances.append(
                        (alert, instance)
                    )

        return alert_instances