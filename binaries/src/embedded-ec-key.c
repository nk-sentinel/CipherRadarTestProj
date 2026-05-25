/*
 * Fixture: compiled binary with an embedded SEC1 EC private key.
 *
 * Tests the YARA-X `embedded_pem_ec_private` rule. Mirrors the same
 * leak vector as `embedded-rsa-key`: a developer compiles a key into
 * a string literal "just for testing" and ships the binary. EC keys
 * use the SEC1 -----BEGIN EC PRIVATE KEY----- marker (different from
 * RSA's PKCS#1 marker and from generic PKCS#8).
 *
 * The key below is a non-secret test fixture. Treat as compromised; do
 * not use it for any real purpose.
 *
 * Build:  make embedded-ec-key
 * Scan:   cradar scan dist/embedded-ec-key --passes 3 --rules-dir <yara-rules>
 */
#include <stdio.h>
#include <string.h>

static const char *embedded_ec_signing_key =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEILlJTcdGAcDLTH5W5XLg8L4QkXqL4kqyHjE7nA4qNm5DoAoGCCqGSM49\n"
    "AwEHoUQDQgAEbFXLwKLVHQwSWqQrZ8YHe9xVnUd6jvJSC4mp9HzD1xKL5y3J9X7c\n"
    "Q0r4kqyHjE7nA4qNm5DZ8YHe9xVnUd6jvJSC4mp9HzD1xKL5y3J9X==\n"
    "-----END EC PRIVATE KEY-----\n";

int main(void) {
    /* Print a slice of the key. Without this, gcc -O2 replaces strlen()
     * with a compile-time constant and elides the string from .rodata,
     * defeating the whole point of the fixture. Printing forces the
     * bytes to remain in the binary. */
    size_t n = strlen(embedded_ec_signing_key);
    printf("EC signing key loaded (%zu bytes):\n%.60s...\n", n, embedded_ec_signing_key);
    return 0;
}
