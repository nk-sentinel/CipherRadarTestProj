"""Insecure crypto patterns — CipherRadar advantage (weakness detection)."""
import random
import string
import ssl
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# EXPECTED: Random | - | - | high | quantum-safe
# Weak PRNG for security-sensitive value
def weak_token():
    return random.randint(0, 999999)  # BAD: not cryptographically secure

# EXPECTED: Random | - | - | high | quantum-safe
# Weak PRNG for password generation
def weak_password(length=16):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))  # BAD

# EXPECTED: AES | CBC | 256 | critical | quantum-safe
# Hardcoded encryption key
HARDCODED_KEY = b"0123456789abcdef0123456789abcdef"  # BAD: hardcoded
def encrypt_hardcoded(plaintext):
    iv = b"\x00" * 16  # BAD: static IV
    cipher = Cipher(algorithms.AES(HARDCODED_KEY), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# EXPECTED: AES | CBC | 256 | high | quantum-safe
# Static IV
STATIC_IV = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"  # BAD
def encrypt_static_iv(key, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(STATIC_IV))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# EXPECTED: TLS | - | - | critical | quantum-vulnerable
# Disabled certificate verification
def insecure_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # BAD
    ctx.verify_mode = ssl.CERT_NONE  # BAD
    return ctx

# EXPECTED: PBKDF2 | - | - | critical | quantum-safe
# Iteration count in variable — very low
iterations = 10
def weak_kdf(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)  # BAD
    return kdf.derive(password)

# EXPECTED: - | - | - | critical | quantum-safe
# Password in source code
DATABASE_PASSWORD = "SuperSecret123!"  # BAD: hardcoded password
API_KEY = "sk-proj-abc123def456ghi789"  # BAD: hardcoded API key

# EXPECTED: MD5 | - | - | high | broken
# MD5 for password hashing
def hash_password_md5(password):
    return hashlib.md5(password.encode()).hexdigest()  # BAD: never use MD5 for passwords
