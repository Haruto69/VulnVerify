from backend.models.normalized_finding import NormalizedFinding
from backend.parsers.base import BaseParser


def normalize_scan(
    parser: BaseParser,
    content: bytes,
    scan_id: str
) -> list[NormalizedFinding]:
    """
    Normalize a raw scanner report using the provided parser.
    """

    return parser.parse(
        content=content,
        scan_id=scan_id
    )