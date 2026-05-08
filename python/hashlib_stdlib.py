"""Python stdlib hashlib patterns — CipherRadar detects, CBOMkit does NOT."""
import hashlib

# EXPECTED: MD5 | - | - | high | broken
def hash_md5(data):
    return hashlib.md5(data).hexdigest()  # BAD

# EXPECTED: SHA-1 | - | - | medium | quantum-vulnerable
def hash_sha1(data):
    return hashlib.sha1(data).hexdigest()  # DEPRECATED

# EXPECTED: SHA-256 | - | - | info | quantum-safe
def hash_sha256(data):
    return hashlib.sha256(data).hexdigest()

# EXPECTED: SHA-384 | - | - | info | quantum-safe
def hash_sha384(data):
    return hashlib.sha384(data).hexdigest()

# EXPECTED: SHA-512 | - | - | info | quantum-safe
def hash_sha512(data):
    return hashlib.sha512(data).hexdigest()

# EXPECTED: SHA3-256 | - | - | info | quantum-safe
def hash_sha3_256(data):
    return hashlib.sha3_256(data).hexdigest()

# EXPECTED: BLAKE2b | - | - | info | quantum-safe
def hash_blake2b(data):
    return hashlib.blake2b(data).hexdigest()

# EXPECTED: BLAKE2s | - | - | info | quantum-safe
def hash_blake2s(data):
    return hashlib.blake2s(data).hexdigest()

# EXPECTED: RIPEMD-160 | - | - | medium | quantum-safe
def hash_ripemd160(data):
    return hashlib.new("ripemd160", data).hexdigest()

# EXPECTED: PBKDF2 | - | - | critical | quantum-safe
def pbkdf2_weak(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password, salt, 100)  # BAD: 100 iterations

# EXPECTED: PBKDF2 | - | - | info | quantum-safe
def pbkdf2_strong(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password, salt, 600000)  # GOOD
