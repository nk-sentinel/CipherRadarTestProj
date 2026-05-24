# Binary-scanning test fixtures

Compiled binaries that exercise cradar's Pass 3 (YARA-X) binary scanner. Each fixture embeds specific cryptographic material in its `.rodata` segment so YARA-X rules in `scanner/yara-rules/` (cradar repo) can be tested against realistic compiled artifacts.

## What's here

| Fixture | What it embeds | YARA rule(s) it should trigger |
|---|---|---|
| `dist/embedded-cert` | A test X.509 PEM certificate as a string literal | `embedded_pem_certificate` |
| `dist/embedded-rsa-key` | A test RSA private key in PEM form | `embedded_pem_rsa_private` |
| `dist/openssl-versions` | OpenSSL version strings (1.0.2u, 1.1.1w, 3.0.12, 3.1.4) + libsodium / BoringSSL / mbed TLS markers | `openssl_version_1_0`, `openssl_version_1_1`, `openssl_version_3_0`, `openssl_version_3_1`, `libsodium_signature`, `boringssl_magic`, `mbedtls_signature` |
| `dist/crypto-constants` | AES forward S-box + Rcon, MD5 IV, SHA-256 IV + first round constants | `aes_sbox_forward`, `aes_rcon`, `md5_constants`, `sha256_constants` |

All four are tiny (~15-20 KB stripped). All built on Ubuntu 24.04 / gcc 13 / x86_64 ELF.

## Why these specific fixtures

These cover the four most common patterns YARA crypto rules look for in compiled binaries:

1. **Embedded certificates** — apps that pin a CA cert by compiling it into a string literal. Common in IoT / embedded firmware where loading at runtime isn't an option.
2. **Embedded private keys** — the leak vector where a developer pastes a key into source "just for testing" and ships the binary. Also seen in malware that uses hardcoded C2 keys.
3. **Library version strings** — statically linked OpenSSL / libsodium / etc. The version is the signal for CVE matching.
4. **Algorithm-specific constants** — S-boxes, round constants, IVs. The signal survives symbol stripping and obfuscation because the algorithm fundamentally needs these byte tables.

## Why not real OpenSSL / Java / Go binaries

A real statically-linked OpenSSL ELF is ~3 MB. A minimal BouncyCastle JAR is ~6 MB. A Go binary using `crypto/aes` is ~5 MB. Committing those would balloon the test project to >20 MB across all fixtures. The synthetic C fixtures above carry the same byte signatures in 15-20 KB each — enough for rule development without the size cost. When the YARA-X integration is more mature, optionally add a `binaries/heavy/` subdir with real-world artifacts.

## Rebuild

Pre-built artifacts in `dist/` are committed for out-of-the-box use. Rebuild from source only when changing a fixture or verifying reproducibility:

```bash
cd binaries
make clean
make
make list   # one-line description per fixture
```

Requires `gcc` (13.x tested). No third-party libraries needed.

## Use from cradar

These are picked up automatically by `cradar scan <project-root>` once the YARA-X scanner (Sub-PR A) registers binary extensions. Direct scan:

```bash
cradar scan binaries/dist/ --passes 3 --format text
```

Per-fixture inspection:

```bash
cradar scan binaries/dist/embedded-rsa-key --passes 3 --format cyclonedx-json | jq
```

## Not yet covered (future fixtures)

- WASM module (Sub-PR A registers `.wasm` but no fixture yet)
- Java JAR with BouncyCastle dependencies — needs a small build-on-demand recipe to avoid committing a 6 MB JAR
- Go binary using `crypto/aes` — same size concern
- Stripped vs unstripped variants — the current Makefile passes `-s`; an unstripped variant would help rules that rely on symbol-name strings
