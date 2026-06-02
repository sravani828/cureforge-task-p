
import hashlib
import hmac
from datetime import datetime, timedelta

from src.models import Approval

SECRET_KEY = b"super_secret_key"


def build_signature_payload(
    action_id: str,
    approval: Approval
) -> str:

    return (
        f"{action_id}:"
        f"{approval.approver_id}:"
        f"{approval.credential_class.value}:"
        f"{approval.issued_at.isoformat()}"
    )


def generate_signature(
    action_id: str,
    approval: Approval
) -> str:

    payload = build_signature_payload(
        action_id,
        approval
    )

    return hmac.new(
        SECRET_KEY,
        payload.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_signature(
    action_id: str,
    approval: Approval
) -> bool:

    payload = build_signature_payload(
        action_id,
        approval
    )

    expected_signature = hmac.new(
        SECRET_KEY,
        payload.encode(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(
        expected_signature,
        approval.signature
    )


def approval_is_fresh(
    approval: Approval,
    max_age_seconds: int = 300
) -> bool:

    age = (
        datetime.utcnow() -
        approval.issued_at
    ).total_seconds()

    return age <= max_age_seconds

