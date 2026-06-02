
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Tuple


class CredentialClass(Enum):
    ENGINEER = "ENGINEER"
    SECURITY = "SECURITY"
    OPERATIONS = "OPERATIONS"
    COMPLIANCE = "COMPLIANCE"


class GateState(Enum):
    PENDING = "PENDING"
    RELEASED = "RELEASED"
    WITHHELD = "WITHHELD"
    TIMED_OUT = "TIMED_OUT"


class GateDecision(Enum):
    RELEASED = "RELEASED"
    WITHHELD = "WITHHELD"
    TIMED_OUT = "TIMED_OUT"


@dataclass
class Approval:
    approver_id: str
    credential_class: CredentialClass
    issued_at: datetime
    signature: str


@dataclass(frozen=True)
class ApprovalPolicy:
    required_credentials: Tuple[
        CredentialClass,
        ...
    ]
    timeout_seconds: int


@dataclass(frozen=True)
class AuditRecord:
    timestamp: datetime
    event: str
    approver_id: str | None
    result_state: GateState


@dataclass
class GateHandle:
    action_id: str
    policy: ApprovalPolicy
    created_at: datetime
    approvals: list[Approval] = field(
        default_factory=list
    )

    _audit_log: Tuple[
        AuditRecord,
        ...
    ] = field(
        default_factory=tuple
    )

    state: GateState = GateState.PENDING

    @property
    def audit_log(self):
        return self._audit_log
