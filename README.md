# CipherRadar Test Project

A deliberately insecure, multi-language project for testing the CipherRadar CBOM
scanner end-to-end. It exercises every detection pass (tree-sitter AST →
OpenGrep taint → YARA-X binary), all supported languages, config/IaC scanning,
certificate + keystore inspection, library/purl resolution, and the
post-quantum migration payload.

This README is the **ground-truth (GT) reference** for FP/FN/TP testing — keep
it in sync with the fixtures.

## Layout

| Path | What it tests |
|---|---|
| `auth/`, `crypto/`, `network/`, `services/`, `python/` | Python — hashing, KDFs, pyca/cryptography, PyCryptodome, stdlib `ssl`, ElGamal, asymmetric, MACs, Fernet |
| `backend/` | Mixed JS / TS / Java — node-forge, WebCrypto, JWT, JCA |
| `javascript/` | JS — node `crypto`, WebCrypto, JWT, `package.json` + `package-lock.json` (library/purl + SRI-suppression) |
| `java/` | Java — full JCA + BouncyCastle (digests, engines, MAC/KDF, signers, PQC ML-KEM/ML-DSA), TLS, key-size chaining; expanded third-party library imports (`CryptoLibraryImports.java`: JJWT, Tink, Spring Security Crypto, Commons Codec, Nimbus) |
| `java/gradle-catalog-app/` | Gradle version-catalog enrichment — `build.gradle.kts` + `gradle/libs.versions.toml` with `libs.*` aliases resolved (incl. `version.ref`) to concrete Maven coordinates + purls |
| `kotlin/`, `csharp/` | Kotlin + C# — JCA-style chaining and the C# `KeySize` property idiom |
| `go/`, `rust/`, `php/`, `ruby/`, `dart/`, `swift/`, `cpp/` | Per-language crypto inventory + lockfiles (`go.mod`, `Cargo.lock`, `Gemfile.lock`, `pubspec.lock`) |
| `certs/` | Certificates: PEM chain, self-signed PEM, DER, PKCS#7, JKS, PKCS#12, BKS, raw private key |
| `config/` | Config scanning — `nginx.conf`, `openssl.cnf`, `java.security`, `.env`, `*.properties` (hardcoded secrets) |
| `k8s/`, `docker/` | Kubernetes TLS Secrets (base64 certs) + Dockerfile |
| `binaries/` | Pass-3 (YARA-X) compiled fixtures — see `binaries/README.md` |
| `vendor/` | **Negative test**: default-ignored vendor dir (must be skipped unless `--no-default-ignores`) |
| `scripts/` | `run-cradar.sh`, `compare.py` (cradar-vs-CBOMkit comparison tooling) |

## Expected Findings (GT)

Categories that **must** be detected. Exact counts vary with rule changes; the
presence of each category is the invariant.

### Classical weak / broken (security)
- MD5, SHA-1, DES, 3DES, RC4, Blowfish
- ECB mode; disabled certificate validation (`CERT_NONE` / trust-all)
- TLS 1.0 / TLS 1.1, SSL (emitted as protocol type `tls` per CycloneDX 1.7)

### Quantum-vulnerable (HNDL priority on export)
- RSA (key-agree/PKE → **critical**), ECDSA / EC / ECDH / DH (**critical**/**high**)
- Ed25519, DSA (signature → **high**), ElGamal
- Each carries `cradar:quantum:priority` + `cradar:quantum:migrationTarget`
  (e.g. RSA → ML-KEM, ECDSA → ML-DSA/SLH-DSA)

### Quantum-safe (priority `none`, never an HNDL signal)
- AES-128 / AES-256 (GCM, CBC, CTR, …), SHA-256 / SHA-384 / SHA-512
- ChaCha20(-Poly1305), HMAC-SHA-2, PBKDF2, HKDF, scrypt
- BouncyCastle PQC: ML-KEM, ML-DSA (quantum-safe)

### Library identification + purl
- Resolved package + version + `purl` for: npm (`node-forge`, `jsonwebtoken`,
  `bcrypt`), PyPI (`cryptography`, `pycryptodome`), Maven (`bcprov-jdk18on`),
  Cargo (`openssl`, `ring`, `rustls`)
- **Maven `<dependencyManagement>` fallback**: `io.jsonwebtoken:jjwt-api` /
  `jjwt-impl` are declared in root `pom.xml` `<dependencies>` *without* a version
  and must resolve to `@0.12.6` via the managed-version block. Tink
  (`com.google.crypto.tink:tink@1.13.0`) resolves from a directly pinned dep.
- **Gradle version catalog** (`java/gradle-catalog-app/`): `libs.*` aliases must
  resolve through `gradle/libs.versions.toml` (including `version.ref`
  indirection) to `pkg:maven/io.jsonwebtoken/jjwt-api@0.12.6` and
  `pkg:maven/com.google.crypto.tink/tink@1.13.0`.
- Detected-but-unresolved libraries (imported in source, absent from any
  manifest — e.g. Spring Security Crypto, Commons Codec, Nimbus JOSE+JWT) carry
  the library name + `purl` **without a version** (graceful fallback).
- Stdlib crypto (hashlib, node:crypto, JCA, WebCrypto) carries the library name
  but **no purl** (by design)

### Certificates (deep)
- Formats: PEM (X.509), DER, PKCS#7; base64 certs in k8s Secrets
- Extensions populated: KeyUsage, ExtendedKeyUsage, BasicConstraints, SubjectAltName
- Each parsed cert decomposes into a CycloneDX `dependencies[]` graph (cert →
  signature-alg + public-key-alg, deduped; per-cert public-key material)
- One finding per cert block (no double-count); `certs/ca-chain.pem` = 2 certs

### Keystores
- JKS + PKCS#12: certificates enumerated; weak/default password → security finding
  (`certs/keystore.jks`, `certs/identity.p12`)
- BKS: presence-only (no pure-Go parser; ADR-041). cradar never downloads wordlists.

### Key size from method-chaining / declarations
- Java `getInstance(...)` + `initialize(N)` / `init(N)` (`java/KeySizeChaining.java`),
  incl. two-arg `initialize(N, SecureRandom)` (`java/KeySizeTwoArg.java`)
- Kotlin `initialize(N)` / two-arg `initialize(N, SecureRandom())` and the
  `(random, N)` ordering (`kotlin/KeySizeTwoArg.kt`)
- C# `rsa.KeySize = N` property (`csharp/KeySizeProperty.cs`) and `Aes` `KeySize`
  (`csharp/AesKeySize.cs`)
- PHP `openssl_pkey_new(['private_key_bits' => N])` (`php/KeySizeRsa.php`)
- Ruby `OpenSSL::PKey::DSA.new(N)` (`ruby/dsa_keysize.rb`)
- C++ OpenSSL `RSA_generate_key_ex(rsa, N, …)` + `AES_set_encrypt_key(key, N, …)`
  where bits is arg 1 (`cpp/keysize_openssl.cpp`)
- EC/Edwards/Montgomery curves backfill key size from the curve name (post-scan
  `keysize.Enrich`): P-256/384/521, secp256k1, Ed25519/X25519 → 256, X448 → 448
- e.g. RSA-2048/3072/4096, DSA-2048, AES-192/256 with `classicalSecurityLevel` set

### Config / secrets / IaC
- `nginx.conf` TLS certs + ciphers, `openssl.cnf`, `java.security` disabled algos
- Hardcoded secrets in `.env` / `*.properties`
- k8s TLS Secrets, Dockerfile

### Pass 3 (binary) — `--deep`
- See `binaries/README.md`. Build dirs (`binaries/dist/`) are scanned under
  `--deep` without needing `--no-default-ignores`.

## Negative / FP guards
- `vendor/badcrypto/weak.py` — must be **skipped** by default ignores.
- `javascript/package-lock.json` `integrity` SRI hashes — must **not** be flagged
  as key material.
- AES-256 / SHA-256 — must be quantum-**safe** (priority `none`), never vulnerable.

## Running

```bash
# Full scan incl. Pass 3 binaries, schema-validated
cradar scan . --deep --format cyclonedx-json --output cbom.json --validate

# Text summary
cradar scan . --format text
```

`scripts/run-cradar.sh` runs the Pass-1-only and full scans used for benchmarking.
