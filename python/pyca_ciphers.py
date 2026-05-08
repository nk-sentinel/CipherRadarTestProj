"""pyca/cryptography cipher patterns for CipherRadar benchmark."""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM, AESSIV, AESOCB3, ChaCha20Poly1305

# EXPECTED: AES | CBC | 256 | low | quantum-safe
def encrypt_aes_cbc(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# EXPECTED: AES | GCM | 256 | info | quantum-safe
def encrypt_aes_gcm(key, plaintext):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return ct, enc.tag

# EXPECTED: AES | ECB | 256 | high | quantum-safe
def encrypt_aes_ecb(key, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.ECB())  # BAD: ECB mode
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# EXPECTED: AES | CTR | 256 | info | quantum-safe
def encrypt_aes_ctr(key, plaintext):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# EXPECTED: AES | OFB | 256 | low | quantum-safe
def encrypt_aes_ofb(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# EXPECTED: AES | CFB | 256 | low | quantum-safe
def encrypt_aes_cfb(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# EXPECTED: AES | XTS | 512 | info | quantum-safe
def encrypt_aes_xts(key, plaintext):
    tweak = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# EXPECTED: 3DES | CBC | 168 | high | quantum-safe
def encrypt_tripledes(key, plaintext):
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))  # DEPRECATED
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# EXPECTED: Camellia | CBC | 256 | info | quantum-safe
def encrypt_camellia(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# EXPECTED: CAST5 | CBC | 128 | medium | quantum-safe
def encrypt_cast5(key, plaintext):
    iv = os.urandom(8)
    cipher = Cipher(algorithms.CAST5(key), modes.CBC(iv))  # WEAK
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# EXPECTED: Blowfish | CBC | 256 | medium | quantum-safe
def encrypt_blowfish(key, plaintext):
    iv = os.urandom(8)
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv))  # WEAK
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# EXPECTED: ARC4 | - | - | critical | broken
def encrypt_arc4(key, plaintext):
    cipher = Cipher(algorithms.ARC4(key), mode=None)  # BAD: RC4
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# EXPECTED: ChaCha20 | - | 256 | info | quantum-safe
def encrypt_chacha20(key, plaintext):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

# === AEAD Ciphers ===

# EXPECTED: AES-GCM | AEAD | 256 | info | quantum-safe
def aead_aesgcm(key, plaintext, aad):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return aesgcm.encrypt(nonce, plaintext, aad)

# EXPECTED: AES-CCM | AEAD | 256 | info | quantum-safe
def aead_aesccm(key, plaintext, aad):
    aesccm = AESCCM(key)
    nonce = os.urandom(13)
    return aesccm.encrypt(nonce, plaintext, aad)

# EXPECTED: AES-SIV | AEAD | 512 | info | quantum-safe
def aead_aessiv(key, plaintext, aad):
    aessiv = AESSIV(key)
    return aessiv.encrypt(plaintext, [aad])

# EXPECTED: ChaCha20-Poly1305 | AEAD | 256 | info | quantum-safe
def aead_chacha(key, plaintext, aad):
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    return chacha.encrypt(nonce, plaintext, aad)
