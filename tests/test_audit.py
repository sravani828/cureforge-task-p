
from datetime import datetime

from src.models import (
    Approval,
    ApprovalPolicy
)

from src.gate import (
    open_gate,
    submit_approval,
    check_gate
)

from src.verifier import generate_signature


def test_audit_log_records_events():

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

    check_gate(
        gate,
        policy
    )

    assert len(gate.audit_log) >= 3

    assert gate.audit_log[0].event == "gate_opened"

    assert gate.audit_log[-1].event in [
        "gate_released",
        "policy_validation_failed"
    ]

