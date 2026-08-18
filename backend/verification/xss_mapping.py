from backend.verification.xss_context import XssSubtype


ZAP_XSS_SUBTYPE_MAP: dict[str, XssSubtype] = {
    "40012": XssSubtype.REFLECTED,
    "40014": XssSubtype.STORED,
    "40016": XssSubtype.STORED,
    "40017": XssSubtype.STORED,
}


def map_zap_xss_subtype(
    alert_id: str | None,
) -> XssSubtype:
    if alert_id is None:
        return XssSubtype.UNKNOWN

    return ZAP_XSS_SUBTYPE_MAP.get(
        str(alert_id),
        XssSubtype.UNKNOWN,
    )


def map_burp_xss_subtype(
    issue_name: str | None,
) -> XssSubtype:
    if not issue_name:
        return XssSubtype.UNKNOWN

    normalized = issue_name.strip().lower()

    if "dom-based" in normalized or "dom based" in normalized:
        return XssSubtype.DOM_BASED

    if "stored" in normalized:
        return XssSubtype.STORED

    if "reflected" in normalized:
        return XssSubtype.REFLECTED

    return XssSubtype.UNKNOWN