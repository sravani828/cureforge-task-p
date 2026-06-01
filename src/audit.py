from datetime import datetime

from src.models import (
    AuditRecord,
    GateState,
    GatedAction
)


def append_audit_record(
    gated_action: GatedAction,
    event: str,
    approver_id: str | None,
    result_state: GateState
) -> None:

    record = AuditRecord(
        timestamp=datetime.utcnow(),
        event=event,
        approver_id=approver_id,
        result_state=result_state
    )

    gated_action.audit_log.append(record)