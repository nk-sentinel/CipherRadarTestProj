# CipherRadar Test Project

A deliberately insecure multi-language project for testing the CipherRadar CBOM scanner.

## Structure

```
auth/                   Python — password hashing, token management
crypto/                 Python — encryption, PyCryptodome
network/                Python — TLS/SSL configuration
services/               Python — API client, data processing
config/                 .env and .properties with hardcoded secrets
certs/                  PEM files (fake keys/certs for testing)
backend/                JS + Java (not yet scanned — M3/M4)
```

## Expected Findings

### Critical
- Disabled certificate validation (CERT_NONE)

### High (broken/deprecated)
- MD5 hashing
- SHA-1 hashing
- DES encryption
- TLS 1.0 / TLS 1.1

### Quantum-Vulnerable
- RSA key generation
- ECDSA / EC key generation
- Ed25519 key generation

### Quantum-Safe
- AES-256 (GCM, CBC, CTR)
- SHA-256, SHA-384, SHA-512
- ChaCha20
- PBKDF2, HKDF, Scrypt

### Config/Secrets
- Hardcoded keys in .env
- Passwords in .properties
- PEM private keys in certs/
