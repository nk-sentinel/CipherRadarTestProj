"""Password hashing module — deliberately uses a mix of good and bad practices."""
import hashlib
import hmac
import os

# BAD: MD5 for password hashing
def hash_password_insecure(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

# BAD: SHA-1 for password hashing
def hash_password_sha1(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()

# GOOD: PBKDF2 with SHA-256 and proper iterations
def hash_password_secure(password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = os.urandom(32)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return salt, derived

# BAD: Low iteration count
def hash_password_weak_iterations(password: str) -> bytes:
    salt = os.urandom(16)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000)

# GOOD: HMAC for API token verification
def verify_api_token(token: str, secret: str) -> str:
    return hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()

# Dynamic algorithm selection via variable
HASH_ALGO = "sha512"
def hash_with_config(data: bytes) -> str:
    return hashlib.new(HASH_ALGO, data).hexdigest()
