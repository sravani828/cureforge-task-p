
from datetime import datetime

from src.models import (
    Approval,
    ApprovalPolicy,
    CredentialClass,
    GateDecision
)

from src.gate import (
    open_gate,
    submit_approval,
    check
)

from src.verifier import (
    generate_signature
)


def test_valid_gate_release():

    policy = ApprovalPolicy(
        required_credentials=(
            CredentialClass.ENGINEER,
            CredentialClass.SECURITY
        ),
        timeout_seconds=300
    )

    gate = open_gate(
        "deploy_prod",
        policy
    )

    engineer = Approval(
        approver_id="alice",
        credential_class=CredentialClass.ENGINEER,
        issued_at=datetime.utcnow(),
        signature=""
    )

    engineer.signature = generate_signature(
        gate.action_id,
        engineer
    )

    security = Approval(
        approver_id="bob",
        credential_class=CredentialClass.SECURITY,
        issued_at=datetime.utcnow(),
        signature=""
    )

    security.signature = generate_signature(
        gate.action_id,
        security
    )

    submit_approval(
        gate,
        engineer
    )

    submit_approval(
        gate,
        security
    )

    result = check(gate)

    assert result == GateDecision.RELEASED

