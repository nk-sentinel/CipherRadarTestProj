"""Examples using PyCryptodome (Crypto namespace)."""
from Crypto.Cipher import AES, DES, DES3, ChaCha20
from Crypto.Hash import SHA256, SHA512, MD5, SHA1, HMAC
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes

# BAD: DES (56-bit key, broken)
def encrypt_des(key: bytes, data: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

# BAD: 3DES (deprecated by NIST)
def encrypt_3des(key: bytes, data: bytes) -> bytes:
    cipher = DES3.new(key, DES3.MODE_CBC, iv=get_random_bytes(8))
    return cipher.encrypt(data)

# GOOD: AES-256-GCM
def encrypt_aes(key: bytes, data: bytes) -> tuple:
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ct, tag

# BAD: MD5 hash
def hash_md5(data: bytes) -> bytes:
    return MD5.new(data).digest()

# BAD: SHA-1 hash
def hash_sha1(data: bytes) -> bytes:
    return SHA1.new(data).digest()

# GOOD: SHA-256
def hash_sha256(data: bytes) -> bytes:
    return SHA256.new(data).digest()

# GOOD: RSA-4096
def generate_rsa_key():
    return RSA.generate(4096)

# BAD: RSA-1024 (too small)
def generate_weak_rsa():
    return RSA.generate(1024)
