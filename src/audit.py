
from datetime import datetime

from src.models import (
    AuditRecord,
    GateHandle,
    GateState
)


def append_audit_record(
    gate: GateHandle,
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

    object.__setattr__(
        gate,
        "_audit_log",
        gate.audit_log + (record,)
    )


def query_audit_log(
    gate: GateHandle
):

    return tuple(
        gate.audit_log
    )

