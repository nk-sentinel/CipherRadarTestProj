/*
 * Fixture: compiled binary with an embedded PKCS#8 (unwrapped) private key.
 *
 * Tests the YARA-X `embedded_pkcs8_private` rule. PKCS#8 is the algorithm-
 * agnostic key format used by openssl pkcs8, BouncyCastle, and most Java
 * keystore exports. The marker is the generic -----BEGIN PRIVATE KEY-----
 * (no algorithm prefix), distinct from the algorithm-specific RSA / EC
 * markers in the other key fixtures.
 *
 * The key below is a non-secret test fixture. Treat as compromised; do
 * not use it for any real purpose.
 *
 * Build:  make embedded-pkcs8-key
 * Scan:   cradar scan dist/embedded-pkcs8-key --passes 3 --rules-dir <yara-rules>
 */
#include <stdio.h>
#include <string.h>

static const char *embedded_pkcs8_signing_key =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrz4eYqxKjMz5K9pT\n"
    "n8ZqL7vC4f7uXq4o8b4kY1WkX3GhRANCAARsVcvAotUdDBJapCtnxgd73FWdR3qO\n"
    "8lILian0fMPXEovnLcn1ftxDSviSrIeMTucDio2bkNn1k9X==\n"
    "-----END PRIVATE KEY-----\n";

int main(void) {
    /* Print a slice of the key. Without this, gcc -O2 replaces strlen()
     * with a compile-time constant and elides the string from .rodata,
     * defeating the whole point of the fixture. Printing forces the
     * bytes to remain in the binary. */
    size_t n = strlen(embedded_pkcs8_signing_key);
    printf("PKCS#8 signing key loaded (%zu bytes):\n%.60s...\n", n, embedded_pkcs8_signing_key);
    return 0;
}
