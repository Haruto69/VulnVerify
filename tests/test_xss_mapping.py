from backend.verification.xss_context import XssSubtype
from backend.verification.xss_mapping import (
    map_burp_xss_subtype,
    map_zap_xss_subtype,
)


def test_zap_40012_maps_to_reflected():
    assert (
        map_zap_xss_subtype("40012")
        == XssSubtype.REFLECTED
    )


def test_zap_40014_maps_to_stored():
    assert (
        map_zap_xss_subtype("40014")
        == XssSubtype.STORED
    )


def test_zap_40016_maps_to_stored():
    assert (
        map_zap_xss_subtype("40016")
        == XssSubtype.STORED
    )


def test_zap_40017_maps_to_stored():
    assert (
        map_zap_xss_subtype("40017")
        == XssSubtype.STORED
    )


def test_unknown_zap_alert_stays_unknown():
    assert (
        map_zap_xss_subtype("99999")
        == XssSubtype.UNKNOWN
    )


def test_missing_zap_alert_stays_unknown():
    assert (
        map_zap_xss_subtype(None)
        == XssSubtype.UNKNOWN
    )


def test_burp_reflected_name_maps_to_reflected():
    assert (
        map_burp_xss_subtype(
            "Cross-site scripting (reflected)"
        )
        == XssSubtype.REFLECTED
    )


def test_burp_stored_name_maps_to_stored():
    assert (
        map_burp_xss_subtype(
            "Cross-site scripting (stored)"
        )
        == XssSubtype.STORED
    )


def test_burp_dom_name_maps_to_dom_based():
    assert (
        map_burp_xss_subtype(
            "Cross-site scripting (DOM-based)"
        )
        == XssSubtype.DOM_BASED
    )


def test_generic_burp_xss_name_stays_unknown():
    assert (
        map_burp_xss_subtype(
            "Cross Site Scripting"
        )
        == XssSubtype.UNKNOWN
    )


def test_missing_burp_name_stays_unknown():
    assert (
        map_burp_xss_subtype(None)
        == XssSubtype.UNKNOWN
    )