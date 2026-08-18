"""
Service-level tests for the shared SQLi verification service.

Each subtype has its own finalize_* entry point. These tests check
dispatch, VerifiedFinding construction, sidecar evidence persistence
and cross-subtype isolation. Rule-level behaviour lives in the
per-subtype test modules.
"""

import pytest

from backend.models.normalized_finding import VulnerabilityCategory
from backend.models.verified_finding import (
    VerificationStatus,
    VerifiedFinding,
)
from backend.services.sqli_verification_service import (
    finalize_boolean_based_sqli_verification,
    finalize_error_based_sqli_verification,
    finalize_time_based_sqli_verification,
    finalize_union_based_sqli_verification,
)
from backend.storage.sqli_evidence_repository import (
    clear_sqli_verification_evidence,
    get_sqli_verification_evidence,
)
from backend.verification.sqli_boolean_based import (
    BooleanComparisonTrial,
)
from tests.sqli_helpers import (
    MYSQL_COLUMN_COUNT_BODY,
    MYSQL_ERROR_BODY,
    STABLE_BODY,
    delayed_verification_trials,
    make_replay_result,
    make_sqli_finding,
    observation,
    stable_baseline,
    stable_timing_baseline,
    undelayed_verification_trials,
)


SCANNER_MARKER = "vv-union-marker-7f3a"

MARKER_BODY = STABLE_BODY.replace(
    "</body>",
    f"{SCANNER_MARKER}</body>",
)

EMPTY_RESULT_BODY = (
    "<html><body><h1>Catalog</h1>No results found.</body></html>"
)


@pytest.fixture(autouse=True)
def clean_evidence_store():
    clear_sqli_verification_evidence()
    yield
    clear_sqli_verification_evidence()


def stored_evidence(finding):
    return get_sqli_verification_evidence(
        scan_id=finding.scan_id,
        finding_id=finding.finding_id,
    )


# ---------------------------------------------------------------------
# Per-subtype call helpers
# ---------------------------------------------------------------------


def run_error_based(finding=None, **overrides):
    finding = finding or make_sqli_finding(
        subtype="ERROR_BASED"
    )

    kwargs = {
        "finding": finding,
        "baseline_responses": stable_baseline(),
        "verification_responses": [
            observation(MYSQL_ERROR_BODY, status=500)
            for _ in range(3)
        ],
        "parameter_dependency_established": True,
    }
    kwargs.update(overrides)

    return finalize_error_based_sqli_verification(**kwargs)


def boolean_trial(index: int = 0) -> BooleanComparisonTrial:
    return BooleanComparisonTrial(
        true_response=observation(STABLE_BODY),
        false_response=observation(EMPTY_RESULT_BODY),
        true_request_reference=f"req-true-{index}",
        false_request_reference=f"req-false-{index}",
    )


def run_boolean_based(finding=None, **overrides):
    finding = finding or make_sqli_finding(
        subtype="BOOLEAN_BASED"
    )

    kwargs = {
        "finding": finding,
        "baseline_responses": stable_baseline(),
        "comparisons": [
            boolean_trial(index) for index in range(3)
        ],
        "parameter_dependency_established": True,
    }
    kwargs.update(overrides)

    return finalize_boolean_based_sqli_verification(**kwargs)


def run_union_based(finding=None, **overrides):
    finding = finding or make_sqli_finding(
        subtype="UNION_BASED"
    )

    kwargs = {
        "finding": finding,
        "baseline_responses": stable_baseline(),
        "verification_responses": [
            observation(MARKER_BODY) for _ in range(3)
        ],
        "union_technique_identified": True,
        "parameter_dependency_established": True,
        "scanner_marker": SCANNER_MARKER,
    }
    kwargs.update(overrides)

    return finalize_union_based_sqli_verification(**kwargs)


def run_time_based(finding=None, **overrides):
    finding = finding or make_sqli_finding(
        subtype="TIME_BASED"
    )

    kwargs = {
        "finding": finding,
        "replay_result": make_replay_result(),
        "baseline_samples": stable_timing_baseline(),
        "verification_samples": delayed_verification_trials(),
    }
    kwargs.update(overrides)

    return finalize_time_based_sqli_verification(**kwargs)


ALL_SUBTYPES = [
    ("ERROR_BASED", run_error_based, "sqli_error_based_rule_v1"),
    ("BOOLEAN_BASED", run_boolean_based, "sqli_boolean_based_rule_v1"),
    ("TIME_BASED", run_time_based, "sqli_time_based_rule_v1"),
    ("UNION_BASED", run_union_based, "sqli_union_based_rule_v1"),
]


# ---------------------------------------------------------------------
# Dispatch, model contract and propagation
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "subtype,runner,method",
    ALL_SUBTYPES,
    ids=[case[0] for case in ALL_SUBTYPES],
)
def test_every_subtype_returns_a_verified_finding(
    subtype,
    runner,
    method,
):
    result = runner()

    assert isinstance(result, VerifiedFinding)
    assert result.schema_version == "1.0"


@pytest.mark.parametrize(
    "subtype,runner,method",
    ALL_SUBTYPES,
    ids=[case[0] for case in ALL_SUBTYPES],
)
def test_every_subtype_propagates_its_verification_method(
    subtype,
    runner,
    method,
):
    assert runner().verification_method == method


@pytest.mark.parametrize(
    "subtype,runner,method",
    ALL_SUBTYPES,
    ids=[case[0] for case in ALL_SUBTYPES],
)
def test_every_subtype_propagates_the_finding_id(
    subtype,
    runner,
    method,
):
    finding = make_sqli_finding(
        finding_id=f"F-{subtype}",
        subtype=subtype,
    )

    assert runner(finding).finding_id == f"F-{subtype}"


@pytest.mark.parametrize(
    "subtype,runner,method",
    ALL_SUBTYPES,
    ids=[case[0] for case in ALL_SUBTYPES],
)
def test_every_subtype_produces_the_expected_true_positive(
    subtype,
    runner,
    method,
):
    result = runner()

    assert (
        result.classification.status
        == VerificationStatus.TRUE_POSITIVE
    )
    assert result.classification.confidence == 0.98


@pytest.mark.parametrize(
    "subtype,runner,method",
    ALL_SUBTYPES,
    ids=[case[0] for case in ALL_SUBTYPES],
)
def test_every_subtype_keeps_confidence_within_bounds(
    subtype,
    runner,
    method,
):
    confidence = runner().classification.confidence

    assert 0.0 <= confidence <= 1.0


@pytest.mark.parametrize(
    "subtype,runner,method",
    ALL_SUBTYPES,
    ids=[case[0] for case in ALL_SUBTYPES],
)
def test_every_subtype_rejects_a_non_sqli_finding(
    subtype,
    runner,
    method,
):
    finding = make_sqli_finding(
        category=VulnerabilityCategory.XSS,
        subtype=subtype,
    )

    with pytest.raises(ValueError, match="non-SQLI"):
        runner(finding)


@pytest.mark.parametrize(
    "subtype,runner,method",
    ALL_SUBTYPES,
    ids=[case[0] for case in ALL_SUBTYPES],
)
def test_a_rejected_finding_saves_no_evidence(
    subtype,
    runner,
    method,
):
    finding = make_sqli_finding(
        category=VulnerabilityCategory.XSS,
        subtype=subtype,
    )

    with pytest.raises(ValueError):
        runner(finding)

    assert stored_evidence(finding) is None


@pytest.mark.parametrize(
    "subtype,runner,method",
    ALL_SUBTYPES,
    ids=[case[0] for case in ALL_SUBTYPES],
)
def test_every_subtype_reports_its_own_reason_code_first(
    subtype,
    runner,
    method,
):
    indicators = runner().evidence.indicators

    assert indicators
    assert indicators[0].startswith("TP_")


# ---------------------------------------------------------------------
# Correct classifier is used for each subtype
# ---------------------------------------------------------------------


def test_error_based_dispatches_to_the_database_error_rule():
    result = run_error_based()

    assert (
        result.evidence.indicators[0]
        == "TP_DATABASE_ERROR"
    )


def test_boolean_based_dispatches_to_the_response_difference_rule():
    result = run_boolean_based()

    assert (
        result.evidence.indicators[0]
        == "TP_BOOLEAN_RESPONSE_DIFFERENCE"
    )


def test_time_based_dispatches_to_the_timing_rule():
    result = run_time_based()

    assert (
        result.evidence.indicators[0]
        == "TP_REPRODUCIBLE_TIMING_DIFFERENCE"
    )


def test_union_based_dispatches_to_the_scanner_marker_rule():
    result = run_union_based()

    assert (
        result.evidence.indicators[0]
        == "TP_UNION_SCANNER_MARKER"
    )


# ---------------------------------------------------------------------
# Sidecar evidence persistence
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "subtype,runner,method",
    ALL_SUBTYPES,
    ids=[case[0] for case in ALL_SUBTYPES],
)
def test_every_subtype_saves_evidence_under_its_own_subtype(
    subtype,
    runner,
    method,
):
    finding = make_sqli_finding(
        finding_id=f"F-{subtype}",
        subtype=subtype,
    )

    runner(finding)

    stored = stored_evidence(finding)

    assert stored is not None
    assert stored["subtype"] == subtype
    assert stored["evidence"]


def test_error_based_evidence_records_the_signature():
    finding = make_sqli_finding(subtype="ERROR_BASED")

    run_error_based(finding)

    evidence = stored_evidence(finding)["evidence"]

    assert evidence["error_signature_id"] == "MYSQL_SYNTAX_001"
    assert evidence["error_db_family"] == "MYSQL"
    assert evidence["baseline_match_count"] == 0
    assert evidence["error_match_count"] == 3


def test_error_based_evidence_is_json_friendly_plain_data():
    finding = make_sqli_finding(subtype="ERROR_BASED")

    run_error_based(finding)

    evidence = stored_evidence(finding)["evidence"]

    assert isinstance(evidence, dict)
    assert isinstance(evidence["verification_matches"], list)

    first_match = evidence["verification_matches"][0][0]

    assert first_match["db_family"] == "MYSQL"
    assert first_match["strength"] == "SUPPORTING"


def test_boolean_based_evidence_records_the_comparison_matrix():
    finding = make_sqli_finding(subtype="BOOLEAN_BASED")

    run_boolean_based(finding)

    evidence = stored_evidence(finding)["evidence"]

    assert evidence["true_request"] == [
        "req-true-0",
        "req-true-1",
        "req-true-2",
    ]
    assert evidence["semantic_difference"] == [
        True,
        True,
        True,
    ]
    assert evidence["repetition_matrix"] == [
        ["BODY_SIMILARITY_SPLIT", 3]
    ]


def test_union_based_evidence_records_the_marker():
    finding = make_sqli_finding(subtype="UNION_BASED")

    run_union_based(finding)

    evidence = stored_evidence(finding)["evidence"]

    assert evidence["union_marker"] == SCANNER_MARKER
    assert evidence["marker_source"] == "scanner"
    assert evidence["marker_present_baseline"] is False
    assert evidence["marker_present_verification"] == [
        True,
        True,
        True,
    ]


def test_union_based_evidence_records_a_column_count_error():
    finding = make_sqli_finding(subtype="UNION_BASED")

    run_union_based(
        finding,
        verification_responses=[
            observation(MYSQL_COLUMN_COUNT_BODY, status=500)
            for _ in range(3)
        ],
        scanner_marker=None,
    )

    evidence = stored_evidence(finding)["evidence"]

    assert (
        evidence["column_count_error_signature"]
        == "MYSQL_COLUMN_COUNT_ERROR"
    )


def test_time_based_evidence_records_the_timing_statistics():
    finding = make_sqli_finding(subtype="TIME_BASED")

    run_time_based(finding)

    evidence = stored_evidence(finding)["evidence"]

    assert evidence["baseline_median"] == 100.0
    assert evidence["baseline_MAD"] == 0.0
    assert evidence["baseline_variation_ratio"] == 0.0
    assert evidence["baseline_response_times"] == [
        100.0,
        105.0,
        95.0,
        100.0,
        100.0,
    ]
    assert evidence["verification_response_times"] == [
        2500.0,
        2600.0,
        2700.0,
    ]
    assert evidence["timing_delta_ms"] == 2500.0
    assert evidence["timing_ratio"] == 26.0
    assert evidence["per_trial_delay_pass"] == [
        True,
        True,
        True,
    ]
    assert (
        evidence["external_timing_interference_observed"]
        is False
    )


def test_time_based_evidence_records_a_failed_delay_pattern():
    finding = make_sqli_finding(subtype="TIME_BASED")

    result = run_time_based(
        finding,
        verification_samples=undelayed_verification_trials(),
    )

    assert (
        result.classification.status
        == VerificationStatus.FALSE_POSITIVE
    )

    evidence = stored_evidence(finding)["evidence"]

    assert evidence["per_trial_delay_pass"] == [
        False,
        False,
        False,
    ]


def test_reverification_replaces_the_stored_evidence():
    finding = make_sqli_finding(subtype="TIME_BASED")

    run_time_based(finding)
    run_time_based(
        finding,
        verification_samples=undelayed_verification_trials(),
    )

    evidence = stored_evidence(finding)["evidence"]

    assert evidence["verification_response_times"] == [
        110.0,
        105.0,
        115.0,
    ]


# ---------------------------------------------------------------------
# Cross-subtype isolation
# ---------------------------------------------------------------------


def test_subtypes_do_not_leak_evidence_into_each_other():
    findings = {}

    for subtype, runner, _ in ALL_SUBTYPES:
        finding = make_sqli_finding(
            scan_id="SCAN-MIXED",
            finding_id=f"F-{subtype}",
            subtype=subtype,
        )
        findings[subtype] = finding
        runner(finding)

    for subtype, finding in findings.items():
        assert stored_evidence(finding)["subtype"] == subtype


def test_running_one_subtype_does_not_change_another_result():
    error_finding = make_sqli_finding(
        finding_id="F-ERR",
        subtype="ERROR_BASED",
    )
    union_finding = make_sqli_finding(
        finding_id="F-UNION",
        subtype="UNION_BASED",
    )

    first = run_error_based(error_finding)
    run_union_based(union_finding)
    second = run_error_based(error_finding)

    assert (
        first.classification.status
        == second.classification.status
    )
    assert (
        first.classification.confidence
        == second.classification.confidence
    )
    assert first.evidence.indicators == second.evidence.indicators


def test_the_same_inputs_always_produce_the_same_verdict():
    for _ in range(3):
        result = run_boolean_based()

        assert (
            result.classification.status
            == VerificationStatus.TRUE_POSITIVE
        )
        assert result.classification.confidence == 0.98


# ---------------------------------------------------------------------
# Failure propagation
# ---------------------------------------------------------------------


def test_error_based_failure_contract_reaches_the_service():
    finding = make_sqli_finding(subtype="ERROR_BASED")

    result = run_error_based(
        finding,
        verification_responses=[
            observation(
                "",
                status=401,
                valid=False,
                failure_reasons=("AUTHENTICATION_REQUIRED",),
            )
            for _ in range(3)
        ],
    )

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )
    assert (
        result.evidence.indicators[0]
        == "INC_INSUFFICIENT_VALID_TRIALS"
    )
    assert stored_evidence(finding) is not None


def test_boolean_based_missing_scanner_pair_reaches_the_service():
    result = run_boolean_based(comparisons=[])

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )
    assert (
        result.evidence.indicators[0]
        == "INC_INSUFFICIENT_SCANNER_EVIDENCE"
    )
    assert result.evidence.response_reference is None


def test_union_based_missing_technique_reaches_the_service():
    result = run_union_based(
        union_technique_identified=False
    )

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )
    assert (
        result.evidence.indicators[0]
        == "INC_INSUFFICIENT_SCANNER_EVIDENCE"
    )


def test_time_based_external_interference_reaches_the_service():
    result = run_time_based(
        external_timing_interference_observed=True
    )

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )
    assert (
        result.evidence.indicators[0]
        == "INC_EXTERNAL_TIMING_EXPLANATION"
    )


def test_time_based_legacy_network_explanation_alias_still_works():
    result = run_time_based(
        credible_network_or_server_explanation=True
    )

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )


def test_time_based_legacy_alias_overrides_the_new_flag():
    result = run_time_based(
        external_timing_interference_observed=True,
        credible_network_or_server_explanation=False,
    )

    assert (
        result.classification.status
        == VerificationStatus.TRUE_POSITIVE
    )


def test_time_based_legacy_verification_confidence_is_ignored():
    result = run_time_based(verification_confidence=0.10)

    assert result.classification.confidence == 0.98


def test_time_based_missing_telemetry_is_not_inconclusive():
    """
    No interference flag is supplied at all: the service must still
    reach a TRUE_POSITIVE on valid timing evidence.
    """

    result = run_time_based()

    assert (
        result.classification.status
        == VerificationStatus.TRUE_POSITIVE
    )


def test_time_based_auth_failure_returns_inconclusive():
    """
    Regression test for a fixed defect: when every baseline request
    hits the failure contract (401 here), context.baseline_statistics
    is None. _save_time_based_evidence() must not crash on that and
    the INCONCLUSIVE verdict from verify_sqli_time_based() must reach
    the caller.
    """

    from tests.sqli_helpers import timing_sample

    finding = make_sqli_finding(subtype="TIME_BASED")

    result = run_time_based(
        finding,
        baseline_samples=[
            timing_sample(number, 100.0, status=401)
            for number in range(1, 6)
        ],
        replay_result=make_replay_result(status=401),
    )

    assert (
        result.classification.status
        == VerificationStatus.INCONCLUSIVE
    )


def test_time_based_auth_failure_persists_evidence_with_null_baseline_stats():
    """
    Missing baseline statistics must be represented as None, not
    fabricated, and evidence persistence must still succeed.
    """

    from tests.sqli_helpers import timing_sample

    finding = make_sqli_finding(subtype="TIME_BASED")

    run_time_based(
        finding,
        baseline_samples=[
            timing_sample(number, 100.0, status=401)
            for number in range(1, 6)
        ],
        replay_result=make_replay_result(status=401),
    )

    evidence = stored_evidence(finding)["evidence"]

    assert evidence["baseline_median"] is None
    assert evidence["baseline_MAD"] is None
    assert evidence["baseline_variation_ratio"] is None
    assert evidence["timing_delta_ms"] is None
    assert evidence["timing_ratio"] is None
    assert evidence["per_trial_delay"] == []
    assert evidence["per_trial_delay_pass"] == []
    assert evidence["baseline_response_times"] == [
        100.0,
        100.0,
        100.0,
        100.0,
        100.0,
    ]
    assert evidence["verification_response_times"] == [
        2500.0,
        2600.0,
        2700.0,
    ]
