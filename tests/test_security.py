
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


def test_replay_attack_rejected():

    policy = ApprovalPolicy(
        required_credentials=(
            CredentialClass.ENGINEER,
        ),
        timeout_seconds=300
    )

    gate_one = open_gate(
        "production_deploy",
        policy
    )

    approval = Approval(
        approver_id="alice",
        credential_class=CredentialClass.ENGINEER,
        issued_at=datetime.utcnow(),
        signature=""
    )

    approval.signature = generate_signature(
        gate_one.action_id,
        approval
    )

    submit_approval(
        gate_one,
        approval
    )

    result_one = check(
        gate_one
    )

    assert (
        result_one ==
        GateDecision.RELEASED
    )

    gate_two = open_gate(
        "delete_database",
        policy
    )

    submit_approval(
        gate_two,
        approval
    )

    result_two = check(
        gate_two
    )

    assert (
        result_two ==
        GateDecision.WITHHELD
    )


def test_same_class_approvals_fail_policy():

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

    approval_one = Approval(
        approver_id="alice",
        credential_class=CredentialClass.ENGINEER,
        issued_at=datetime.utcnow(),
        signature=""
    )

    approval_one.signature = generate_signature(
        gate.action_id,
        approval_one
    )

    approval_two = Approval(
        approver_id="bob",
        credential_class=CredentialClass.ENGINEER,
        issued_at=datetime.utcnow(),
        signature=""
    )

    approval_two.signature = generate_signature(
        gate.action_id,
        approval_two
    )

    submit_approval(
        gate,
        approval_one
    )

    submit_approval(
        gate,
        approval_two
    )

    result = check(
        gate
    )

    assert (
        result ==
        GateDecision.WITHHELD
    )


def test_stale_approval_rejected():

    policy = ApprovalPolicy(
        required_credentials=(
            CredentialClass.ENGINEER,
        ),
        timeout_seconds=300
    )

    gate = open_gate(
        "deploy_prod",
        policy
    )

    approval = Approval(
        approver_id="alice",
        credential_class=CredentialClass.ENGINEER,
        issued_at=(
            datetime.utcnow() -
            timedelta(hours=1)
        ),
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

    result = check(
        gate
    )

    assert (
        result ==
        GateDecision.WITHHELD
    )
