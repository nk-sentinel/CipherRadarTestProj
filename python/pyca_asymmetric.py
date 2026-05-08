"""pyca/cryptography asymmetric key patterns for CipherRadar benchmark."""
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh, ed25519, ed448, x25519, x448, padding, utils
from cryptography.hazmat.primitives import hashes

# EXPECTED: RSA | - | 1024 | critical | quantum-vulnerable
def gen_rsa_1024():
    return rsa.generate_private_key(65537, 1024)  # BAD: weak key

# EXPECTED: RSA | - | 2048 | medium | quantum-vulnerable
def gen_rsa_2048():
    return rsa.generate_private_key(65537, 2048)

# EXPECTED: RSA | - | 4096 | low | quantum-vulnerable
def gen_rsa_4096():
    return rsa.generate_private_key(65537, 4096)

# EXPECTED: ECDSA | P-256 | 256 | low | quantum-vulnerable
def gen_ec_p256():
    return ec.generate_private_key(ec.SECP256R1())

# EXPECTED: ECDSA | P-384 | 384 | low | quantum-vulnerable
def gen_ec_p384():
    return ec.generate_private_key(ec.SECP384R1())

# EXPECTED: ECDSA | P-521 | 521 | low | quantum-vulnerable
def gen_ec_p521():
    return ec.generate_private_key(ec.SECP521R1())

# EXPECTED: ECDSA | secp256k1 | 256 | low | quantum-vulnerable
def gen_ec_secp256k1():
    return ec.generate_private_key(ec.SECP256K1())

# EXPECTED: Ed25519 | - | 256 | low | quantum-vulnerable
def gen_ed25519():
    return ed25519.Ed25519PrivateKey.generate()

# EXPECTED: Ed448 | - | 448 | low | quantum-vulnerable
def gen_ed448():
    return ed448.Ed448PrivateKey.generate()

# EXPECTED: X25519 | - | 256 | low | quantum-vulnerable
def gen_x25519():
    return x25519.X25519PrivateKey.generate()

# EXPECTED: X448 | - | 448 | low | quantum-vulnerable
def gen_x448():
    return x448.X448PrivateKey.generate()

# EXPECTED: DSA | - | 2048 | medium | quantum-vulnerable
def gen_dsa():
    return dsa.generate_private_key(2048)

# EXPECTED: DH | - | 2048 | medium | quantum-vulnerable
def gen_dh():
    params = dh.generate_parameters(generator=2, key_size=2048)
    return params.generate_private_key()

# EXPECTED: RSA | PSS | - | info | quantum-vulnerable
def sign_rsa_pss(private_key, data):
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

# EXPECTED: RSA | PKCS1v15 | - | medium | quantum-vulnerable
def sign_rsa_pkcs1(private_key, data):
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())  # BAD: padding oracle

# EXPECTED: RSA | OAEP | - | low | quantum-vulnerable
def encrypt_rsa_oaep(public_key, plaintext):
    return public_key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# EXPECTED: RSA | PKCS1v15 | - | medium | quantum-vulnerable
def encrypt_rsa_pkcs1(public_key, plaintext):
    return public_key.encrypt(plaintext, padding.PKCS1v15())  # BAD

# EXPECTED: ECDSA | - | - | low | quantum-vulnerable
def sign_ecdsa(private_key, data):
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
