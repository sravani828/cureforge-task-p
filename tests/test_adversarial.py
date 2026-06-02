
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


def test_invalid_signature_rejected():

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
        issued_at=datetime.utcnow(),
        signature="tampered_signature"
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


def test_duplicate_approver_rejected():

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


def test_tampered_complete_approval_set_fails():

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
        signature="fake_signature"
    )

    submit_approval(
        gate,
        engineer
    )

    submit_approval(
        gate,
        security
    )

    result = check(
        gate
    )

    assert (
        result ==
        GateDecision.WITHHELD
    )


def test_timeout_race_condition_fails_closed():

    policy = ApprovalPolicy(
        required_credentials=(
            CredentialClass.ENGINEER,
        ),
        timeout_seconds=1
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

    gate.created_at = (
        datetime.utcnow() -
        timedelta(seconds=5)
    )

    result = check(
        gate
    )

    assert (
        result ==
        GateDecision.TIMED_OUT
    )


def test_closed_gate_rejects_new_approval():

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

    check(gate)

    second = Approval(
        approver_id="bob",
        credential_class=CredentialClass.SECURITY,
        issued_at=datetime.utcnow(),
        signature=""
    )

    second.signature = generate_signature(
        gate.action_id,
        second
    )

    result = submit_approval(
        gate,
        second
    )

    assert result == gate.state


def test_invalid_signature_keeps_withheld_sticky():

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
        issued_at=datetime.utcnow(),
        signature="invalid"
    )

    submit_approval(
        gate,
        approval
    )

    result_one = check(
        gate
    )

    result_two = check(
        gate
    )

    assert (
        result_one ==
        GateDecision.WITHHELD
    )

    assert (
        result_two ==
        GateDecision.WITHHELD
    )

