"""
Automatic verification orchestration.

Runs immediately after a freshly-uploaded scan's findings have been
normalized (see backend/api/scans.py::upload_scan), automatically
constructing and running the exact same verification each supported
finding family already runs when the user configures it manually
through the frontend's VerifyForm:

  SQLI -> ERROR_BASED             (backend/api/findings.py::_verify_error_based_sqli_finding)
  CSRF -> "Password Changed." +
          Origin/Referer (BOTH)   (backend/api/findings.py::_verify_csrf_finding)
  XSS  -> two default payloads    (backend/api/findings.py::_verify_reflected_xss_finding)

This module intentionally reuses those three functions directly
rather than reimplementing verification, and rather than making an
HTTP request from the backend to itself -- they already build the
correct replay/context/classification pipeline and already persist
the result via save_verified_finding (see backend/services/
pipeline_service.py). Nothing about SQLi/CSRF/XSS classification
rules, replay behavior, or the manual verification endpoint is
changed by this module.

Every classification produced here (TRUE_POSITIVE / FALSE_POSITIVE /
INCONCLUSIVE) comes from that same, unmodified verification engine --
this module never assigns or guesses a classification itself.
"""

import logging

from backend.models.normalized_finding import NormalizedFinding
from backend.models.verification_trigger import (
    CsrfOriginTestConfig,
    CsrfStateCheckConfig,
    CsrfVerificationConfig,
    SqliErrorBasedVerificationConfig,
    SqliVerificationConfig,
    VerificationTriggerRequest,
    XssPayloadVariant,
    XssReflectedVerificationConfig,
    XssVerificationConfig,
)
from backend.replay.csrf import CsrfOriginMutation
from backend.services.scan_service import (
    get_normalized_findings,
    get_verified_findings,
    set_verification_progress,
    try_claim_scan_for_auto_verification,
)


logger = logging.getLogger(__name__)


# The exact working manual CSRF configuration (see frontend/src/App.jsx
# VerifyForm's CSRF branch): a deterministic acceptance indicator of
# "Password Changed." (no extra whitespace) plus an Origin/Referer
# defense test mutating BOTH headers. The defense_test (known
# token/header removal) checkbox is left disabled by default in the
# manual form too, so it is not auto-enabled here either.
_CSRF_DETERMINISTIC_ACCEPTANCE_INDICATOR = "Password Changed."

# The two default XSS verification payloads this task specifies.
_XSS_DEFAULT_PAYLOAD_VARIANTS = [
    XssPayloadVariant(
        variant_id="auto-v1",
        payload='<script>alert("hello")</script>',
    ),
    XssPayloadVariant(
        variant_id="auto-v2",
        payload='<script>alert("xss")</script>',
    ),
]


def build_auto_trigger(
    finding: NormalizedFinding,
) -> VerificationTriggerRequest | None:
    """
    Build the VerificationTriggerRequest automatic verification would
    submit for this finding, or None when this finding's vulnerability
    family is not one of the currently supported automatic families
    (SQLI, CSRF, XSS). This never invents a new trigger shape --
    every field used here already exists in
    backend/models/verification_trigger.py and is exactly what the
    manual frontend form sends today.
    """

    category = finding.vulnerability.category

    if category == "SQLI":
        return VerificationTriggerRequest(
            sqli=SqliVerificationConfig(
                error_based=SqliErrorBasedVerificationConfig()
            )
        )

    if category == "CSRF":
        return VerificationTriggerRequest(
            csrf=CsrfVerificationConfig(
                state_check=CsrfStateCheckConfig(
                    deterministic_acceptance_indicator=(
                        _CSRF_DETERMINISTIC_ACCEPTANCE_INDICATOR
                    )
                ),
                origin_test=CsrfOriginTestConfig(
                    mutation=CsrfOriginMutation.BOTH
                ),
            )
        )

    if category == "XSS":
        return VerificationTriggerRequest(
            xss=XssVerificationConfig(
                reflected=XssReflectedVerificationConfig(
                    payload_variants=list(
                        _XSS_DEFAULT_PAYLOAD_VARIANTS
                    )
                )
            )
        )

    # Any other vulnerability family (INFORMATION_DISCLOSURE, CORS,
    # SECURITY_MISCONFIGURATION, ...): no automatic verification
    # behavior is invented -- the finding is simply left unverified,
    # exactly as it already was before this feature existed.
    return None


def _dispatch(
    finding: NormalizedFinding,
    trigger: VerificationTriggerRequest,
):
    """
    Route to the exact same per-family verification function the
    manual /verify endpoint dispatches to
    (backend/api/findings.py::verify_finding). Reused directly rather
    than duplicated so automatic and manual verification can never
    drift apart.
    """

    # Imported lazily, inside the function, to avoid a module-level
    # import cycle between the API router package and this service
    # module (backend.api.findings imports from backend.services.*).
    from backend.api.findings import (
        _verify_csrf_finding,
        _verify_error_based_sqli_finding,
        _verify_reflected_xss_finding,
    )

    if trigger.csrf is not None:
        return _verify_csrf_finding(finding=finding, trigger=trigger)

    if trigger.sqli is not None:
        return _verify_error_based_sqli_finding(
            finding=finding, trigger=trigger
        )

    return _verify_reflected_xss_finding(
        finding=finding, trigger=trigger
    )


def run_auto_verification(scan_id: str) -> None:
    """
    Automatically verify every supported, not-yet-verified finding in
    one freshly-uploaded scan.

    Idempotent at the scan level (try_claim_scan_for_auto_verification
    ensures this only actually runs once per scan_id, even if called
    more than once) and at the finding level (any finding that already
    has a stored verified result -- e.g. because the user manually
    verified it while automatic verification was still running for
    other findings -- is skipped, never re-verified).
    """

    if not try_claim_scan_for_auto_verification(scan_id):
        return

    findings = get_normalized_findings(scan_id)

    already_verified_ids = {
        verified.finding_id
        for verified in get_verified_findings(scan_id)
    }

    candidates = []

    for finding in findings:
        if finding.finding_id in already_verified_ids:
            continue

        trigger = build_auto_trigger(finding)

        if trigger is None:
            continue

        candidates.append((finding, trigger))

    total = len(candidates)

    progress = {
        "status": "RUNNING" if total > 0 else "COMPLETED",
        "total": total,
        "completed": 0,
        "current": None,
        "counts": {
            "TRUE_POSITIVE": 0,
            "FALSE_POSITIVE": 0,
            "INCONCLUSIVE": 0,
        },
        "errors": [],
    }
    set_verification_progress(scan_id, dict(progress))

    if total == 0:
        return

    try:
        for finding, trigger in candidates:
            progress["current"] = _describe_activity(
                finding, trigger
            )
            set_verification_progress(scan_id, dict(progress))

            try:
                verified = _dispatch(finding, trigger)
                status = verified.classification.status

                if status in progress["counts"]:
                    progress["counts"][status] += 1
            except Exception as exc:
                # A single finding failing to verify (replay timeout,
                # malformed scanner data the verifier itself rejects,
                # an unexpected error) must not abort verification of
                # the remaining findings, and must never be recorded
                # as a fabricated classification.
                logger.warning(
                    "Automatic verification failed for finding "
                    "%s (scan %s): %s",
                    finding.finding_id,
                    scan_id,
                    exc,
                )
                progress["errors"].append(
                    {
                        "finding_id": finding.finding_id,
                        "message": str(exc),
                    }
                )

            progress["completed"] += 1
            set_verification_progress(scan_id, dict(progress))

        progress["status"] = "COMPLETED"
        progress["current"] = None
        set_verification_progress(scan_id, dict(progress))

    except Exception as exc:
        # An unexpected failure in the orchestration loop itself
        # (not a single finding's verification) -- surfaced as a
        # genuine failure state, never silently reinterpreted as
        # FALSE_POSITIVE for whatever findings didn't get processed.
        logger.exception(
            "Automatic verification failed for scan %s", scan_id
        )
        progress["status"] = "FAILED"
        progress["error"] = str(exc)
        set_verification_progress(scan_id, dict(progress))


def _describe_activity(
    finding: NormalizedFinding,
    trigger: VerificationTriggerRequest,
) -> str:
    if trigger.sqli is not None:
        return (
            f"{finding.source.original_name} — "
            "ERROR_BASED verification"
        )

    if trigger.csrf is not None:
        return (
            f"{finding.source.original_name} — "
            "CSRF verification"
        )

    return (
        f"{finding.source.original_name} — "
        "Reflected XSS verification"
    )
