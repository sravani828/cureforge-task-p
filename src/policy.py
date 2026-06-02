
from src.models import (
    Approval,
    ApprovalPolicy
)


def validate_approvals(
    policy: ApprovalPolicy,
    approvals: list[Approval]
) -> bool:

    required = set(
        policy.required_credentials
    )

    received = set()

    approvers = set()

    for approval in approvals:

        if approval.approver_id in approvers:
            return False

        approvers.add(
            approval.approver_id
        )

        if (
            approval.credential_class
            in required
        ):
            received.add(
                approval.credential_class
            )

    return required.issubset(
        received
    )

