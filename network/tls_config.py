"""TLS/SSL configuration for network services."""
import ssl
import socket

# GOOD: Modern TLS 1.3 context
def create_secure_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx

# BAD: TLS 1.0 (deprecated)
def create_legacy_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    return ctx

# BAD: Disabled certificate verification — MITM vulnerable
def create_insecure_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

# BAD: TLS 1.1 (deprecated)
def create_tls11_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    return ctx

# GOOD: TLS 1.2 minimum
def create_standard_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx

# BAD: Using deprecated wrap_socket
def connect_legacy(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1)
