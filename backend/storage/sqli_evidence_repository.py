from copy import deepcopy


_sqli_evidence: dict[
    str,
    dict[str, dict],
] = {}


def save_sqli_verification_evidence(
    *,
    scan_id: str,
    finding_id: str,
    subtype: str,
    evidence: dict,
) -> None:
    if scan_id not in _sqli_evidence:
        _sqli_evidence[scan_id] = {}

    _sqli_evidence[scan_id][finding_id] = {
        "subtype": subtype,
        "evidence": deepcopy(evidence),
    }


def get_sqli_verification_evidence(
    *,
    scan_id: str,
    finding_id: str,
) -> dict | None:
    scan_evidence = _sqli_evidence.get(
        scan_id,
        {},
    )

    evidence = scan_evidence.get(
        finding_id
    )

    if evidence is None:
        return None

    return deepcopy(evidence)


def clear_sqli_verification_evidence() -> None:
    _sqli_evidence.clear()
