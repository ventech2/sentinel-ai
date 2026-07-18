"""Allowed remediation status transitions."""

from app.models.constants import RemediationStatus


ALLOWED_TRANSITIONS: dict[RemediationStatus, frozenset[RemediationStatus]] = {
    RemediationStatus.PROPOSED: frozenset(
        {RemediationStatus.PENDING_APPROVAL, RemediationStatus.VERIFYING, RemediationStatus.REJECTED, RemediationStatus.FAILED}
    ),
    RemediationStatus.PENDING_APPROVAL: frozenset({RemediationStatus.APPROVED, RemediationStatus.REJECTED}),
    RemediationStatus.APPROVED: frozenset({RemediationStatus.VERIFYING, RemediationStatus.FAILED}),
    RemediationStatus.VERIFYING: frozenset({RemediationStatus.PR_OPENED, RemediationStatus.FAILED}),
    RemediationStatus.PR_OPENED: frozenset(),
    RemediationStatus.REJECTED: frozenset(),
    RemediationStatus.FAILED: frozenset(),
}


class InvalidRemediationTransition(ValueError):
    """Raised when a service tries to skip a remediation safety state."""


def transition(current: str, target: RemediationStatus) -> str:
    current_status = RemediationStatus(current)
    if target not in ALLOWED_TRANSITIONS[current_status]:
        raise InvalidRemediationTransition(f"Cannot transition remediation from {current_status} to {target}.")
    return str(target)
