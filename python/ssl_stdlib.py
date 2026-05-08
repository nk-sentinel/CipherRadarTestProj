"""Python ssl module patterns — CipherRadar detects, CBOMkit does NOT."""
import ssl

# EXPECTED: TLS | 1.3 | - | info | quantum-safe
def tls_client_good():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx

# EXPECTED: TLS | 1.0 | - | critical | quantum-vulnerable
def tls_v1_bad():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # BAD: deprecated
    return ctx

# EXPECTED: TLS | 1.1 | - | high | quantum-vulnerable
def tls_v11_bad():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)  # DEPRECATED
    return ctx

# EXPECTED: TLS | 1.2 | - | info | quantum-safe
def tls_v12():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx

# EXPECTED: TLS | - | - | critical | quantum-vulnerable
def tls_no_verify():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # BAD
    ctx.verify_mode = ssl.CERT_NONE  # BAD: disables certificate verification
    return ctx

# EXPECTED: TLS | - | - | info | quantum-safe
def tls_verify_required():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED  # GOOD
    ctx.check_hostname = True
    return ctx

# EXPECTED: TLS | - | - | high | quantum-vulnerable
def tls_wrap_socket_deprecated():
    import socket
    sock = socket.socket()
    wrapped = ssl.wrap_socket(sock)  # BAD: deprecated API
    return wrapped

# EXPECTED: TLS | 1.2 | - | info | quantum-safe
def tls_minimum_version():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx

# EXPECTED: RC4 | - | - | critical | broken
def tls_weak_ciphers():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.set_ciphers("RC4-SHA")  # BAD: weak cipher
    return ctx
