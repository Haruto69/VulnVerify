from abc import ABC, abstractmethod

from backend.models.normalized_finding import NormalizedFinding


class BaseParser(ABC):

    @abstractmethod
    def parse(
        self,
        content: bytes,
        scan_id: str
    ) -> list[NormalizedFinding]:
        """
        Convert a raw scanner report into NormalizedFinding objects.

        Args:
            content: Raw uploaded scanner report.
            scan_id: Internal ID assigned to the uploaded scan.

        Returns:
            A list of normalized findings.
        """
        pass