from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import List


class GateState(Enum):
    PENDING = "PENDING"
    RELEASED = "RELEASED"
    WITHHELD = "WITHHELD"
    TIMED_OUT = "TIMED_OUT"


@dataclass(frozen=True)
class Approval:
    approver_id: str
    credential_class: str
    timestamp: datetime
    signature: str


@dataclass
class ApprovalPolicy:
    required_credentials: List[str]
    timeout_seconds: int


@dataclass
class AuditRecord:
    timestamp: datetime
    event: str
    approver_id: str | None
    result_state: GateState


@dataclass
class GatedAction:
    action_id: str
    created_at: datetime
    approvals: List[Approval] = field(default_factory=list)
    audit_log: List[AuditRecord] = field(default_factory=list)
    state: GateState = GateState.PENDING