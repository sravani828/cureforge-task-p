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


def test_valid_gate_release():

    policy = ApprovalPolicy(
        required_credentials=[
            "ENGINEER",
            "SECURITY"
        ],
        timeout_seconds=300
    )

    gate = open_gate("deploy_production")

    engineer_message = (
        "alice" +
        "ENGINEER"
    )

    engineer_approval = Approval(
        approver_id="alice",
        credential_class="ENGINEER",
        timestamp=datetime.utcnow(),
        signature=generate_signature(
            engineer_message
        )
    )

    security_message = (
        "bob" +
        "SECURITY"
    )

    security_approval = Approval(
        approver_id="bob",
        credential_class="SECURITY",
        timestamp=datetime.utcnow(),
        signature=generate_signature(
            security_message
        )
    )

    submit_approval(
        gate,
        engineer_approval
    )

    submit_approval(
        gate,
        security_approval
    )

    result = check_gate(
        gate,
        policy
    )

    assert result == GateState.RELEASED