"""pyca/cryptography hash patterns for CipherRadar benchmark."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import Hash

# EXPECTED: MD5 | - | - | high | broken
def hash_md5(data):
    h = Hash(hashes.MD5())  # BAD
    h.update(data)
    return h.finalize()

# EXPECTED: SHA-1 | - | - | medium | quantum-vulnerable
def hash_sha1(data):
    h = Hash(hashes.SHA1())  # DEPRECATED
    h.update(data)
    return h.finalize()

# EXPECTED: SHA-224 | - | - | info | quantum-safe
def hash_sha224(data):
    h = Hash(hashes.SHA224())
    h.update(data)
    return h.finalize()

# EXPECTED: SHA-256 | - | - | info | quantum-safe
def hash_sha256(data):
    h = Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()

# EXPECTED: SHA-384 | - | - | info | quantum-safe
def hash_sha384(data):
    h = Hash(hashes.SHA384())
    h.update(data)
    return h.finalize()

# EXPECTED: SHA-512 | - | - | info | quantum-safe
def hash_sha512(data):
    h = Hash(hashes.SHA512())
    h.update(data)
    return h.finalize()

# EXPECTED: SHA-512/224 | - | - | info | quantum-safe
def hash_sha512_224(data):
    h = Hash(hashes.SHA512_224())
    h.update(data)
    return h.finalize()

# EXPECTED: SHA-512/256 | - | - | info | quantum-safe
def hash_sha512_256(data):
    h = Hash(hashes.SHA512_256())
    h.update(data)
    return h.finalize()

# EXPECTED: SHA3-256 | - | - | info | quantum-safe
def hash_sha3_256(data):
    h = Hash(hashes.SHA3_256())
    h.update(data)
    return h.finalize()

# EXPECTED: SHA3-384 | - | - | info | quantum-safe
def hash_sha3_384(data):
    h = Hash(hashes.SHA3_384())
    h.update(data)
    return h.finalize()

# EXPECTED: SHA3-512 | - | - | info | quantum-safe
def hash_sha3_512(data):
    h = Hash(hashes.SHA3_512())
    h.update(data)
    return h.finalize()

# EXPECTED: SHAKE-128 | - | - | info | quantum-safe
def hash_shake128(data):
    h = Hash(hashes.SHAKE128(32))
    h.update(data)
    return h.finalize()

# EXPECTED: SHAKE-256 | - | - | info | quantum-safe
def hash_shake256(data):
    h = Hash(hashes.SHAKE256(64))
    h.update(data)
    return h.finalize()

# EXPECTED: BLAKE2b | - | - | info | quantum-safe
def hash_blake2b(data):
    h = Hash(hashes.BLAKE2b(64))
    h.update(data)
    return h.finalize()

# EXPECTED: BLAKE2s | - | - | info | quantum-safe
def hash_blake2s(data):
    h = Hash(hashes.BLAKE2s(32))
    h.update(data)
    return h.finalize()

# EXPECTED: SM3 | - | - | info | quantum-safe
def hash_sm3(data):
    h = Hash(hashes.SM3())
    h.update(data)
    return h.finalize()
