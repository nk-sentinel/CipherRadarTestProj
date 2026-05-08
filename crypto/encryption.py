"""Encryption utilities using the cryptography library."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os

# --- Symmetric encryption ---

# GOOD: AES-256-GCM (authenticated encryption)
def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> tuple:
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ct, encryptor.tag

# BAD: AES-ECB (no IV, patterns leak)
def encrypt_aes_ecb(key: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    return encryptor.update(padded) + encryptor.finalize()

# GOOD: AES-CBC with proper IV
def encrypt_aes_cbc(key: bytes, plaintext: bytes) -> tuple:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    return iv, encryptor.update(padded) + encryptor.finalize()

# GOOD: ChaCha20Poly1305
def encrypt_chacha20(key: bytes, plaintext: bytes) -> tuple:
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    return nonce, encryptor.update(plaintext) + encryptor.finalize()

# --- Asymmetric keys ---

# QUANTUM-VULNERABLE: RSA-2048
def generate_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

# BAD: RSA-1024 (too small)
def generate_weak_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)

# QUANTUM-VULNERABLE: ECDSA P-256
def generate_ec_key():
    return ec.generate_private_key(ec.SECP256R1())

# QUANTUM-VULNERABLE: Ed25519
def generate_ed25519_key():
    return ed25519.Ed25519PrivateKey.generate()

# --- Key derivation ---

# GOOD: PBKDF2 with high iterations
def derive_key_pbkdf2(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return kdf.derive(password)

# GOOD: HKDF for key expansion
def derive_key_hkdf(input_key: bytes, salt: bytes, info: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(input_key)

# GOOD: Scrypt for password hashing
def derive_key_scrypt(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**20,
        r=8,
        p=1,
    )
    return kdf.derive(password)
