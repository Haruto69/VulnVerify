from backend.verification.xss_observations import (
    XssReplayAttemptObservation,
)


def test_minimal_attempt_observation():
    observation = XssReplayAttemptObservation(
        payload_variant_id="variant-1",
    )

    assert observation.payload_variant_id == "variant-1"
    assert observation.replay is None
    assert observation.marker_fired is False
    assert observation.browser_completed_successfully is False


def test_browser_execution_observation():
    observation = XssReplayAttemptObservation(
        payload_variant_id="variant-1",
        browser_completed_successfully=True,
        marker_fired=True,
        marker_fired_in_correct_context=True,
    )

    assert observation.browser_completed_successfully is True
    assert observation.marker_fired is True
    assert observation.marker_fired_in_correct_context is True


def test_dom_sink_observation():
    observation = XssReplayAttemptObservation(
        payload_variant_id="variant-1",
        browser_completed_successfully=True,
        dom_attacker_controlled_data_reached_sink=True,
    )

    assert (
        observation.dom_attacker_controlled_data_reached_sink
        is True
    )