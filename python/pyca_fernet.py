"""pyca/cryptography Fernet patterns — CBOMkit detects this, does CipherRadar?"""
from cryptography.fernet import Fernet, MultiFernet

# EXPECTED: Fernet | - | 256 | info | quantum-safe
def fernet_generate():
    return Fernet.generate_key()

# EXPECTED: Fernet | - | 256 | info | quantum-safe
def fernet_encrypt(key, data):
    f = Fernet(key)
    return f.encrypt(data)

# EXPECTED: Fernet | - | 256 | info | quantum-safe
def fernet_decrypt(key, token):
    f = Fernet(key)
    return f.decrypt(token)

# EXPECTED: MultiFernet | - | 256 | info | quantum-safe
def multi_fernet_encrypt(keys, data):
    fernets = [Fernet(k) for k in keys]
    mf = MultiFernet(fernets)
    return mf.encrypt(data)

# EXPECTED: Fernet | - | 256 | info | quantum-safe
def fernet_encrypt_at_time(key, data, current_time):
    f = Fernet(key)
    return f.encrypt_at_time(data, current_time)
