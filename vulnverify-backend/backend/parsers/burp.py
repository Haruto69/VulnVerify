from backend.models.normalized_finding import NormalizedFinding
from backend.parsers.base import BaseParser


class BurpParser(BaseParser):

    def parse(
        self,
        content: bytes,
        scan_id: str
    ) -> list[NormalizedFinding]:
        raise NotImplementedError(
            "Burp parsing is not implemented yet."
        )