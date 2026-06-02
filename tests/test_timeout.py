
from datetime import (
    datetime,
    timedelta
)

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


def test_multiday_stale_gate_times_out():

    policy = ApprovalPolicy(
        required_credentials=(
            CredentialClass.ENGINEER,
        ),
        timeout_seconds=100
    )

    gate = open_gate(
        "deploy_prod",
        policy
    )

    approval = Approval(
        approver_id="alice",
        credential_class=CredentialClass.ENGINEER,
        issued_at=datetime.utcnow(),
        signature=""
    )

    approval.signature = generate_signature(
        gate.action_id,
        approval
    )

    submit_approval(
        gate,
        approval
    )

    # Simulate:
    # 24 hours + 50 seconds old

    gate.created_at = (
        datetime.utcnow() -
        timedelta(
            days=1,
            seconds=50
        )
    )

    result = check(
        gate
    )

    assert (
        result ==
        GateDecision.TIMED_OUT
    )

