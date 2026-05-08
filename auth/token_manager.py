"""JWT and session token management."""
import hashlib
import hmac
import os

SECRET_KEY = "super-secret-key-hardcoded-in-source"  # BAD: hardcoded secret

def generate_session_id() -> str:
    """Generate a session ID using SHA-256."""
    random_bytes = os.urandom(32)
    return hashlib.sha256(random_bytes).hexdigest()

def sign_token(payload: str) -> str:
    """Sign a token with HMAC-SHA256."""
    return hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()

def verify_token(payload: str, signature: str) -> bool:
    """Verify token signature — uses constant-time comparison."""
    expected = sign_token(payload)
    return hmac.compare_digest(expected, signature)
