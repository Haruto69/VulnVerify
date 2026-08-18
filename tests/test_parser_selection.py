import pytest

from backend.parsers import get_parser
from backend.parsers.burp import BurpParser
from backend.parsers.zap import ZapParser


def test_get_zap_parser():
    parser = get_parser("ZAP")

    assert isinstance(parser, ZapParser)


def test_get_burp_parser():
    parser = get_parser("BURP")

    assert isinstance(parser, BurpParser)


def test_parser_selection_is_case_insensitive():
    parser = get_parser("zap")

    assert isinstance(parser, ZapParser)


def test_unsupported_scanner():
    with pytest.raises(ValueError):
        get_parser("UNKNOWN")