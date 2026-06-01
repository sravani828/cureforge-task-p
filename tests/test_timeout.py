
from datetime import datetime, timedelta

from src.models import (
    ApprovalPolicy,
    GateState
)

from src.gate import (
    open_gate,
    check_gate
)


def test_gate_timeout():

    policy = ApprovalPolicy(
        required_credentials=[
            "ENGINEER"
        ],
        timeout_seconds=1
    )

    gate = open_gate("deploy")

    # Force gate to appear expired
    gate.created_at = (
        datetime.utcnow() -
        timedelta(seconds=10)
    )

    result = check_gate(
        gate,
        policy
    )

    assert result == GateState.TIMED_OUT

