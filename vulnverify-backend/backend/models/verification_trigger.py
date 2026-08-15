from pydantic import BaseModel, Field, model_validator

from backend.replay.csrf import (
    CsrfDefenseLocation,
    CsrfOriginMutation,
)


class CsrfDefenseTestConfig(BaseModel):
    """
    Configuration for removing a known CSRF token or custom header
    during controlled replay.
    """

    name: str = Field(
        min_length=1,
    )

    location: CsrfDefenseLocation


class CsrfOriginTestConfig(BaseModel):
    """
    Configuration for controlled cross-site Origin/Referer replay.
    """

    mutation: CsrfOriginMutation


class CsrfStateCheckConfig(BaseModel):
    """
    Application-level success evidence available during replay.

    Generic before/after application state probes are handled
    internally when an application-specific observer is available.
    """

    deterministic_acceptance_indicator: str | None = None


class CsrfVerificationConfig(BaseModel):
    defense_test: CsrfDefenseTestConfig | None = None
    origin_test: CsrfOriginTestConfig | None = None
    state_check: CsrfStateCheckConfig | None = None

    browser_context_required: bool = False

    @model_validator(mode="after")
    def validate_at_least_one_check(
        self,
    ):
        if (
            self.defense_test is None
            and self.origin_test is None
            and self.state_check is None
            and not self.browser_context_required
        ):
            raise ValueError(
                "At least one CSRF verification check must be configured"
            )

        return self


class VerificationTriggerRequest(BaseModel):
    csrf: CsrfVerificationConfig

    timeout_seconds: float = Field(
        default=10.0,
        gt=0.0,
        le=60.0,
    )