from src.models import ApprovalPolicy, Approval


def validate_approvals(
    policy: ApprovalPolicy,
    approvals: list[Approval]
) -> bool:

    required_credentials = set(policy.required_credentials)

    received_credentials = set()

    approvers = set()

    for approval in approvals:

        # Prevent duplicate approver usage
        if approval.approver_id in approvers:
            return False

        approvers.add(approval.approver_id)

        # Only count required credential classes
        if approval.credential_class in required_credentials:
            received_credentials.add(
                approval.credential_class
            )

    return required_credentials.issubset(
        received_credentials
    )
    