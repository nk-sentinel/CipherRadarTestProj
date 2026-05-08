"""API client with various crypto patterns."""
import hashlib
import ssl
import hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization

# Hardcoded API secret
API_SECRET = b"hardcoded-api-secret-key-12345678"

class APIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

    def sign_request(self, payload: bytes) -> bytes:
        """Sign request with RSA-PSS + SHA-256."""
        return self.key.sign(
            payload,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def compute_hmac(self, message: bytes) -> str:
        """Compute HMAC for message authentication."""
        return hmac.new(API_SECRET, message, hashlib.sha256).hexdigest()

    def fingerprint(self, data: bytes) -> str:
        """Compute SHA-512 fingerprint."""
        return hashlib.sha512(data).hexdigest()

    def legacy_hash(self, data: bytes) -> str:
        """BAD: Using MD5 for data integrity."""
        return hashlib.md5(data).hexdigest()

    def get_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for API calls."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx
