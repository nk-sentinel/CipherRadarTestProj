"""Data processing with various hash and encryption patterns."""
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os

# Constant propagation test cases
ALGORITHM = "sha384"
CIPHER_MODE = "aes-256-cbc"

def checksum_file(filepath: str) -> str:
    """Compute SHA-384 checksum using variable-based algo selection."""
    h = hashlib.new(ALGORITHM)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def encrypt_sensitive_data(data: bytes) -> tuple:
    """AES-256-CTR encryption for sensitive data."""
    key = os.urandom(32)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return key, nonce, ct

def hash_pii(email: str) -> str:
    """Hash PII with SHA-256 for pseudonymization."""
    return hashlib.sha256(email.encode()).hexdigest()

def double_hash(data: bytes) -> str:
    """SHA-256 double hash (Bitcoin-style)."""
    first = hashlib.sha256(data).digest()
    return hashlib.sha256(first).hexdigest()

# BAD: Using SHA-1 for integrity
def legacy_checksum(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

# Multiple algorithms in one function
def compute_all_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
        "sha3_256": hashlib.sha3_256(data).hexdigest(),
        "blake2b": hashlib.blake2b(data).hexdigest(),
    }
