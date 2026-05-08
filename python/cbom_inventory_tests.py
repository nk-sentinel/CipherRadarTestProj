"""Test cases for CBOM inventory OpenGrep rules (Python).
These test cross-statement patterns that Pass 1 cannot detect alone.
"""
import os
import ssl
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes


# ── Rule 3: KDF → Derived Key → Cipher Chain ──
# EXPECTED: CBOM links PBKDF2 derivation to AES cipher usage
def kdf_to_cipher_chain(password, salt):
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=310000,
    ).derive(password)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor


# ── Rule 3 variant: Scrypt → Cipher ──
def scrypt_to_cipher_chain(password, salt):
    key = Scrypt(
        salt=salt,
        length=32,
        n=2**20,
        r=8,
        p=1,
    ).derive(password)

    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    return cipher.encryptor()


# ── Rule 4: TLS Version Enforcement ──
# EXPECTED: CBOM records minimum TLS 1.3 enforcement
def tls_version_pinning():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


# ── Rule 6: Config-Driven Algorithm ──
# EXPECTED: CBOM tracks algorithm from environment
def config_driven_hash():
    algo = os.environ.get("HASH_ALGORITHM")
    if algo:
        import hashlib
        return hashlib.new(algo, b"data")
    return None


def config_driven_hash_v2():
    algo = os.getenv("HASH_ALGORITHM")
    if algo:
        import hashlib
        return hashlib.new(algo, b"data")
    return None


# ── Rule 8: Certificate → TLS Context ──
# EXPECTED: CBOM links certificate file to TLS configuration
def cert_to_tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain("/etc/ssl/certs/server.pem", "/etc/ssl/private/server.key")
    return ctx


def ca_cert_to_tls():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations("/etc/ssl/certs/ca-bundle.crt")
    return ctx


# ── Rule 12: Certificate Validation Chain ──
# EXPECTED: CBOM records verification mode for compliance
def strict_cert_validation():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


# ── Rule 13: Password Hash Inventory ──
# EXPECTED: CBOM inventories bcrypt usage
def password_hash_bcrypt(password):
    import bcrypt
    return bcrypt.hashpw(password, bcrypt.gensalt(12))


def password_hash_bcrypt_default(password):
    import bcrypt
    return bcrypt.hashpw(password, bcrypt.gensalt())
