from datetime import datetime

from src.models import (
    Approval,
    ApprovalPolicy,
    GateState
)

from src.gate import (
    open_gate,
    submit_approval,
    check_gate
)

from src.verifier import generate_signature


def test_invalid_signature_rejected():

    policy = ApprovalPolicy(
        required_credentials=[
            "ENGINEER"
        ],
        timeout_seconds=300
    )

    gate = open_gate("deploy")

    approval = Approval(
        approver_id="alice",
        credential_class="ENGINEER",
        timestamp=datetime.utcnow(),
        signature="tampered_signature"
    )

    submit_approval(
        gate,
        approval
    )

    result = check_gate(
        gate,
        policy
    )

    assert result == GateState.WITHHELD


def test_duplicate_approval_rejected():

    policy = ApprovalPolicy(
        required_credentials=[
            "ENGINEER"
        ],
        timeout_seconds=300
    )

    gate = open_gate("deploy")

    message = (
        "alice" +
        "ENGINEER"
    )

    approval = Approval(
        approver_id="alice",
        credential_class="ENGINEER",
        timestamp=datetime.utcnow(),
        signature=generate_signature(
            message
        )
    )

    submit_approval(
        gate,
        approval
    )

    submit_approval(
        gate,
        approval
    )

    result = check_gate(
        gate,
        policy
    )

    assert result == GateState.WITHHELD