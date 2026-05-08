"""pyca/cryptography KDF patterns for CipherRadar benchmark."""
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash, ConcatKDFHMAC
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives import hashes

# EXPECTED: PBKDF2 | - | - | critical | quantum-safe
def pbkdf2_low_iter(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100)  # BAD
    return kdf.derive(password)

# EXPECTED: PBKDF2 | - | - | medium | quantum-safe
def pbkdf2_medium_iter(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=10000)  # WARN
    return kdf.derive(password)

# EXPECTED: PBKDF2 | - | - | info | quantum-safe
def pbkdf2_high_iter(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)  # GOOD
    return kdf.derive(password)

# EXPECTED: scrypt | - | - | info | quantum-safe
def scrypt_strong(password, salt):
    kdf = Scrypt(salt=salt, length=32, n=2**20, r=8, p=1)  # GOOD
    return kdf.derive(password)

# EXPECTED: scrypt | - | - | low | quantum-safe
def scrypt_ok(password, salt):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)  # OK
    return kdf.derive(password)

# EXPECTED: HKDF | - | - | info | quantum-safe
def hkdf_derive(secret, salt, info):
    kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return kdf.derive(secret)

# EXPECTED: HKDF-Expand | - | - | info | quantum-safe
def hkdf_expand(key, info):
    kdf = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info)
    return kdf.derive(key)

# EXPECTED: ConcatKDF | - | - | info | quantum-safe
def concat_kdf(secret, otherinfo):
    kdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=otherinfo)
    return kdf.derive(secret)

# EXPECTED: ConcatKDF-HMAC | - | - | info | quantum-safe
def concat_kdf_hmac(secret, salt, otherinfo):
    kdf = ConcatKDFHMAC(algorithm=hashes.SHA256(), length=32, salt=salt, otherinfo=otherinfo)
    return kdf.derive(secret)

# EXPECTED: X963KDF | - | - | info | quantum-safe
def x963_kdf(secret, sharedinfo):
    kdf = X963KDF(algorithm=hashes.SHA256(), length=32, sharedinfo=sharedinfo)
    return kdf.derive(secret)
