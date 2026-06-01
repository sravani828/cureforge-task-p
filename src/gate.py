
from datetime import datetime

from src.models import (
    GatedAction,
    Approval,
    ApprovalPolicy,
    GateState
)

from src.policy import validate_approvals
from src.verifier import verify_signature
from src.audit import append_audit_record


def open_gate(action_id: str) -> GatedAction:

    gated_action = GatedAction(
        action_id=action_id,
        created_at=datetime.utcnow()
    )

    append_audit_record(
        gated_action,
        "gate_opened",
        None,
        GateState.PENDING
    )

    return gated_action


def submit_approval(
    gated_action: GatedAction,
    approval: Approval
) -> None:

    # Prevent processing after completion
    if gated_action.state != GateState.PENDING:

        append_audit_record(
            gated_action,
            "approval_rejected_closed_gate",
            approval.approver_id,
            gated_action.state
        )

        return

    # Verify signature
    message = (
        approval.approver_id +
        approval.credential_class
    )

    if not verify_signature(
        message,
        approval.signature
    ):

        gated_action.state = GateState.WITHHELD

        append_audit_record(
            gated_action,
            "invalid_signature",
            approval.approver_id,
            GateState.WITHHELD
        )

        return

    # Prevent duplicate approvals
    for existing in gated_action.approvals:

        if existing.approver_id == approval.approver_id:

            gated_action.state = GateState.WITHHELD

            append_audit_record(
                gated_action,
                "duplicate_approval",
                approval.approver_id,
                GateState.WITHHELD
            )

            return

    gated_action.approvals.append(approval)

    append_audit_record(
        gated_action,
        "approval_received",
        approval.approver_id,
        GateState.PENDING
    )


def check_gate(
    gated_action: GatedAction,
    policy: ApprovalPolicy
) -> GateState:

    # Failure-closed:
    # once withheld, never release
    if gated_action.state == GateState.WITHHELD:

        append_audit_record(
            gated_action,
            "withheld_state_enforced",
            None,
            GateState.WITHHELD
        )

        return GateState.WITHHELD

    elapsed_seconds = (
        datetime.utcnow() -
        gated_action.created_at
    ).seconds

    # Timeout handling
    if elapsed_seconds > policy.timeout_seconds:

        gated_action.state = GateState.TIMED_OUT

        append_audit_record(
            gated_action,
            "gate_timed_out",
            None,
            GateState.TIMED_OUT
        )

        return GateState.TIMED_OUT

    # Policy validation
    valid = validate_approvals(
        policy,
        gated_action.approvals
    )

    if valid:

        gated_action.state = GateState.RELEASED

        append_audit_record(
            gated_action,
            "gate_released",
            None,
            GateState.RELEASED
        )

        return GateState.RELEASED

    gated_action.state = GateState.WITHHELD

    append_audit_record(
        gated_action,
        "policy_validation_failed",
        None,
        GateState.WITHHELD
    )

    return GateState.WITHHELD

