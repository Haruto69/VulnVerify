from backend.parsers.base import BaseParser


def get_parser(scanner: str) -> BaseParser:
    """
    Return the parser implementation for the requested scanner.
    """

    scanner_name = scanner.strip().upper()

    if scanner_name == "ZAP":
        from backend.parsers.zap import ZapParser
        return ZapParser()

    if scanner_name == "BURP":
        from backend.parsers.burp import BurpParser
        return BurpParser()

    raise ValueError(f"Unsupported scanner: {scanner}")