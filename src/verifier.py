import hmac
import hashlib

SECRET_KEY = b"super_secret_key"


def generate_signature(message: str) -> str:
    return hmac.new(
        SECRET_KEY,
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_signature(message: str, signature: str) -> bool:
    expected_signature = generate_signature(message)

    return hmac.compare_digest(
        expected_signature,
        signature
    )