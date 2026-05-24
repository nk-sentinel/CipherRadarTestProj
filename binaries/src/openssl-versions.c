/*
 * Fixture: compiled binary that exposes multiple OpenSSL version strings.
 *
 * Tests YARA-X rules that look for OpenSSL/libsodium/BoringSSL/mbedTLS
 * library identifiers inside compiled artifacts. The pattern this catches:
 * a container layer or static binary that links a specific (often outdated)
 * OpenSSL build whose CVE history you want surfaced in the CBOM.
 *
 * Multiple versions are included so the YARA-X rules see vulnerable
 * (1.0.x), deprecated (1.1.x), and current (3.x) markers in one fixture.
 *
 * Build:  make openssl-versions
 * Scan:   cradar scan dist/openssl-versions --passes 3 --rules-dir <yara-rules>
 */
#include <stdio.h>

/* Each marker mimics what `strings <binary> | grep OpenSSL` would produce
 * against a real statically linked artifact. */
static const char *v_legacy_1_0    = "OpenSSL 1.0.2u  20 Dec 2019";
static const char *v_deprecated_1_1 = "OpenSSL 1.1.1w  11 Sep 2023";
static const char *v_current_3_0   = "OpenSSL 3.0.12 24 Oct 2023";
static const char *v_current_3_1   = "OpenSSL 3.1.4 24 Oct 2023";

/* Other crypto libraries for rule coverage. */
static const char *libsodium_marker = "libsodium 1.0.19";
static const char *boringssl_marker = "BoringSSL build 0";
static const char *mbedtls_marker   = "mbed TLS 3.5.1";

int main(void) {
    printf("%s\n%s\n%s\n%s\n",
           v_legacy_1_0, v_deprecated_1_1, v_current_3_0, v_current_3_1);
    printf("%s\n%s\n%s\n",
           libsodium_marker, boringssl_marker, mbedtls_marker);
    return 0;
}
