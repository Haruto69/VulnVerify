from backend.models.normalized_finding import NormalizedFinding
from backend.parsers.base import BaseParser


class ZapParser(BaseParser):

    def parse(
        self,
        content: bytes,
        scan_id: str
    ) -> list[NormalizedFinding]:
        raise NotImplementedError(
            "ZAP parsing will be implemented after the report structure is finalized."
        )