
from datetime import datetime

import pytest

from src.models import (
    Approval,
    ApprovalPolicy,
    CredentialClass
)

from src.gate import (
    open_gate,
    submit_approval
)

from src.verifier import (
    generate_signature
)

from src.audit import (
    query_audit_log
)


def test_audit_log_is_append_only():

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

    log = query_audit_log(
        gate
    )

    with pytest.raises(
        TypeError
    ):

        log[0] = "tampered"

    with pytest.raises(
        AttributeError
    ):

        log.clear()


def test_audit_log_query_returns_tuple():

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

    log = query_audit_log(
        gate
    )

    assert isinstance(
        log,
        tuple
    )


def test_audit_log_records_gate_open():

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

    log = query_audit_log(
        gate
    )

    assert (
        log[0].event ==
        "gate_opened"
    )


def test_audit_log_grows_after_approval():

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

    initial_size = len(
        query_audit_log(gate)
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

    updated_size = len(
        query_audit_log(gate)
    )

    assert updated_size > initial_size


def test_audit_log_records_approval_event():

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

    log = query_audit_log(
        gate
    )

    assert (
        log[-1].event ==
        "approval_received"
    )

