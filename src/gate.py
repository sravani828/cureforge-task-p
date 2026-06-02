
from datetime import datetime

from src.models import (
    Approval,
    ApprovalPolicy,
    GateDecision,
    GateHandle,
    GateState
)

from src.audit import (
    append_audit_record
)

from src.policy import (
    validate_approvals
)

from src.verifier import (
    verify_signature,
    approval_is_fresh
)


def timeout_handler(
    gate: GateHandle
) -> None:

    # configurable no-op stub
    return


def open_gate(
    action: str,
    policy: ApprovalPolicy
) -> GateHandle:

    gate = GateHandle(
        action_id=action,
        policy=policy,
        created_at=datetime.utcnow()
    )

    append_audit_record(
        gate,
        "gate_opened",
        None,
        GateState.PENDING
    )

    return gate


def submit_approval(
    handle: GateHandle,
    approval: Approval
) -> GateState:

    if handle.state != GateState.PENDING:

        append_audit_record(
            handle,
            "approval_rejected_closed_gate",
            approval.approver_id,
            handle.state
        )

        return handle.state

    if not verify_signature(
        handle.action_id,
        approval
    ):

        handle.state = GateState.WITHHELD

        append_audit_record(
            handle,
            "invalid_signature",
            approval.approver_id,
            GateState.WITHHELD
        )

        return GateState.WITHHELD

    if not approval_is_fresh(
        approval
    ):

        handle.state = GateState.WITHHELD

        append_audit_record(
            handle,
            "stale_approval",
            approval.approver_id,
            GateState.WITHHELD
        )

        return GateState.WITHHELD

    for existing in handle.approvals:

        if (
            existing.approver_id ==
            approval.approver_id
        ):

            handle.state = GateState.WITHHELD

            append_audit_record(
                handle,
                "duplicate_approval",
                approval.approver_id,
                GateState.WITHHELD
            )

            return GateState.WITHHELD

    handle.approvals.append(
        approval
    )

    append_audit_record(
        handle,
        "approval_received",
        approval.approver_id,
        GateState.PENDING
    )

    return GateState.PENDING


def check(
    handle: GateHandle
) -> GateDecision:

    if handle.state == GateState.WITHHELD:

        return GateDecision.WITHHELD

    elapsed = (
        datetime.utcnow() -
        handle.created_at
    ).total_seconds()

    if (
        elapsed >
        handle.policy.timeout_seconds
    ):

        handle.state = GateState.TIMED_OUT

        timeout_handler(handle)

        append_audit_record(
            handle,
            "gate_timed_out",
            None,
            GateState.TIMED_OUT
        )

        return GateDecision.TIMED_OUT

    valid = validate_approvals(
        handle.policy,
        handle.approvals
    )

    if valid:

        handle.state = GateState.RELEASED

        append_audit_record(
            handle,
            "gate_released",
            None,
            GateState.RELEASED
        )

        return GateDecision.RELEASED

    handle.state = GateState.WITHHELD

    append_audit_record(
        handle,
        "policy_validation_failed",
        None,
        GateState.WITHHELD
    )

    return GateDecision.WITHHELD

