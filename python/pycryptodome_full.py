"""PyCryptodome patterns — CipherRadar detects, CBOMkit does NOT."""
from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC4, ChaCha20_Poly1305
from Crypto.PublicKey import RSA, ECC, DSA
from Crypto.Hash import SHA256, SHA1, MD5, SHA384, SHA512, HMAC, BLAKE2b
from Crypto.Random import get_random_bytes

# EXPECTED: AES | GCM | 256 | info | quantum-safe
def aes_gcm(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM)  # GOOD
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ct, tag

# EXPECTED: AES | ECB | 256 | high | quantum-safe
def aes_ecb(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)  # BAD: ECB
    return cipher.encrypt(plaintext)

# EXPECTED: AES | CBC | 256 | low | quantum-safe
def aes_cbc(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv, cipher.encrypt(plaintext)

# EXPECTED: AES | SIV | 512 | info | quantum-safe
def aes_siv(key, plaintext, header):
    cipher = AES.new(key, AES.MODE_SIV)
    cipher.update(header)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct, tag

# EXPECTED: DES | ECB | 56 | critical | broken
def des_ecb(key, data):
    cipher = DES.new(key, DES.MODE_ECB)  # BAD
    return cipher.encrypt(data)

# EXPECTED: 3DES | CBC | 168 | high | quantum-safe
def des3_cbc(key, data):
    cipher = DES3.new(key, DES3.MODE_CBC)  # DEPRECATED
    return cipher.iv, cipher.encrypt(data)

# EXPECTED: ARC4 | - | - | critical | broken
def rc4_encrypt(key, data):
    cipher = ARC4.new(key)  # BAD
    return cipher.encrypt(data)

# EXPECTED: ChaCha20-Poly1305 | AEAD | 256 | info | quantum-safe
def chacha20_poly1305(key, plaintext, header):
    cipher = ChaCha20_Poly1305.new(key=key)
    cipher.update(header)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ct, tag

# EXPECTED: RSA | - | 2048 | medium | quantum-vulnerable
def rsa_2048():
    return RSA.generate(2048)

# EXPECTED: RSA | - | 1024 | critical | quantum-vulnerable
def rsa_1024():
    return RSA.generate(1024)  # BAD: weak key

# EXPECTED: ECDSA | P-256 | 256 | low | quantum-vulnerable
def ecc_p256():
    return ECC.generate(curve="P-256")

# EXPECTED: SHA-256 | - | - | info | quantum-safe
def hash_sha256(data):
    return SHA256.new(data).hexdigest()

# EXPECTED: MD5 | - | - | high | broken
def hash_md5(data):
    return MD5.new(data).hexdigest()  # BAD

# EXPECTED: SHA-1 | - | - | medium | quantum-vulnerable
def hash_sha1(data):
    return SHA1.new(data).hexdigest()  # DEPRECATED

# EXPECTED: BLAKE2b | - | - | info | quantum-safe
def hash_blake2b(data):
    return BLAKE2b.new(data=data, digest_bytes=32).hexdigest()
