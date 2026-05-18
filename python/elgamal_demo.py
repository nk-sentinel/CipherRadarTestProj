"""PyCryptodome ElGamal asymmetric encryption — CipherRadar benchmark fixture."""
from Crypto.PublicKey import ElGamal
from Crypto import Random

# EXPECTED: ElGamal | - | 2048 | medium | quantum-vulnerable
def gen_elgamal():
    return ElGamal.generate(2048, Random.new().read)

# EXPECTED: ElGamal | - | - | medium | quantum-vulnerable
def construct_elgamal(p, g, y, x):
    return ElGamal.construct((p, g, y, x))
