"""Remediation & Security Regression Package for ZeroDay v2.0."""

from zeroday.remediation.patching import (
    PatchGenerator,
    ProposedPatch,
)
from zeroday.remediation.recommendations import RemediationAdvisor
from zeroday.remediation.regression import (
    RegressionTestSpec,
    SecurityRegressionEngine,
)
from zeroday.remediation.verification import (
    AutomatedRetestVerifier,
    RetestResult,
)


__all__ = [
    "AutomatedRetestVerifier",
    "PatchGenerator",
    "ProposedPatch",
    "RegressionTestSpec",
    "RemediationAdvisor",
    "RetestResult",
    "SecurityRegressionEngine",
]
