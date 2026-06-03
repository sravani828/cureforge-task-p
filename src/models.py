
from dataclasses import (
    dataclass,
    field
)

from datetime import datetime

from enum import Enum

from typing import Callable


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


GateDecision = GateState


@dataclass
class Approval:

    approver_id: str
    credential_class: CredentialClass
    issued_at: datetime
    signature: str


@dataclass(frozen=True)
class ApprovalPolicy:

    required_credentials: tuple[
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

    state: GateState = GateState.PENDING

    timeout_handler: Callable | None = None

    _audit_log: tuple[
        AuditRecord,
        ...
    ] = field(
        default_factory=tuple,
        init=False,
        repr=False
    )

    def __setattr__(
        self,
        name,
        value
    ):

        if (
            hasattr(self, "_audit_log")
            and name == "_audit_log"
        ):

            raise AttributeError(
                "audit log is immutable"
            )

        super().__setattr__(
            name,
            value
        )

    @property
    def audit_log(self):

        return self._audit_log

