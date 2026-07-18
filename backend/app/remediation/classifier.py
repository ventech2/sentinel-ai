"""Map detector categories to the remediation safety tiers in the technical spec."""

from enum import IntEnum
from typing import Protocol


class FindingCategory(Protocol):
    category: str


class RemediationTier(IntEnum):
    AUTO_FIXABLE = 1
    HUMAN_APPROVAL = 2
    FLAGGED_ONLY = 3


TIER_ONE_CATEGORIES = frozenset(
    {
        "hardcoded_secret",
        "insecure_config",
        "typosquatted_dependency",
        "committed_env_file",
    }
)
TIER_TWO_CATEGORIES = frozenset(
    {
        "hardcoded_auth_bypass",
        "auth_bypass",
        "obfuscated_dynamic_execution",
        "obfuscated_code",
        "suspicious_dynamic_execution",
    }
)
TIER_THREE_CATEGORIES = frozenset(
    {
        "suspicious_outbound_connection",
        "suspicious_install_script",
    }
)


def classify_finding(finding: FindingCategory) -> RemediationTier:
    """Classify a finding conservatively; unknown categories are flagged-only."""
    if finding.category in TIER_ONE_CATEGORIES:
        return RemediationTier.AUTO_FIXABLE
    if finding.category in TIER_TWO_CATEGORIES:
        return RemediationTier.HUMAN_APPROVAL
    return RemediationTier.FLAGGED_ONLY


def tier_guidance(tier: RemediationTier) -> str:
    if tier is RemediationTier.AUTO_FIXABLE:
        return "A deterministic patch can be prepared on an isolated Sentinel branch."
    if tier is RemediationTier.HUMAN_APPROVAL:
        return "This fix is proposed only and requires explicit human approval before verification or PR creation."
    return "This finding is flagged-only because automated changes could disrupt valid business behavior."
