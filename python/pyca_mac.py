"""pyca/cryptography MAC patterns for CipherRadar benchmark."""
import os
from cryptography.hazmat.primitives import hmac as crypto_hmac, hashes, cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305

# EXPECTED: HMAC-SHA256 | - | - | info | quantum-safe
def hmac_sha256(key, data):
    h = crypto_hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

# EXPECTED: HMAC-SHA384 | - | - | info | quantum-safe
def hmac_sha384(key, data):
    h = crypto_hmac.HMAC(key, hashes.SHA384())
    h.update(data)
    return h.finalize()

# EXPECTED: HMAC-SHA512 | - | - | info | quantum-safe
def hmac_sha512(key, data):
    h = crypto_hmac.HMAC(key, hashes.SHA512())
    h.update(data)
    return h.finalize()

# EXPECTED: HMAC-MD5 | - | - | high | broken
def hmac_md5(key, data):
    h = crypto_hmac.HMAC(key, hashes.MD5())  # BAD
    h.update(data)
    return h.finalize()

# EXPECTED: HMAC-SHA1 | - | - | medium | quantum-vulnerable
def hmac_sha1(key, data):
    h = crypto_hmac.HMAC(key, hashes.SHA1())  # DEPRECATED
    h.update(data)
    return h.finalize()

# EXPECTED: AES-CMAC | - | - | info | quantum-safe
def cmac_aes(key, data):
    c = cmac.CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()

# EXPECTED: 3DES-CMAC | - | - | high | quantum-safe
def cmac_3des(key, data):
    c = cmac.CMAC(algorithms.TripleDES(key))  # DEPRECATED
    c.update(data)
    return c.finalize()

# EXPECTED: Poly1305 | - | - | info | quantum-safe
def poly1305_mac(key, data):
    p = Poly1305(key)
    p.update(data)
    return p.finalize()
