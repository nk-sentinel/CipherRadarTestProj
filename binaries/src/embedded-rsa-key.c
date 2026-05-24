/*
 * Fixture: compiled binary with an embedded RSA private key.
 *
 * Tests YARA-X rules that scan binaries for hardcoded private-key material.
 * The leak vector this catches: a developer pastes a service-account key
 * into a string literal "just for testing" and ships the binary. cradar
 * should detect the `-----BEGIN RSA PRIVATE KEY-----` marker plus the
 * base64 body and surface this as a critical-severity private-key asset.
 *
 * The key below is a non-secret test fixture. Treat as compromised; do
 * not use it for any real purpose.
 *
 * Build:  make embedded-rsa-key
 * Scan:   cradar scan dist/embedded-rsa-key --passes 3 --rules-dir <yara-rules>
 */
#include <stdio.h>
#include <string.h>

static const char *hardcoded_signing_key =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
    "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm\n"
    "o3qGy0t6z8K7C6Tj5T1tH1L2g6T4MmH6vCe8Pq2y5o6K4mF2qy0a9bFq5R8j0E1c\n"
    "8QIhAOe9pIfMjuYV8u0yiX0PVT1mJ0+nVF3qzMv2yQ7oH+OvAiEAvB5G6L4nWPnY\n"
    "1xVbV8jJ9d8a5o9p6Z9bF1m2y0K7C6kCIGqg8m+vR4r6t1lY5T7qVz3F4f6c1B0e\n"
    "u8Y7+Sj9k1JZAiBd2hQwT3rZ4o2qWlAjJpZk4PqEZ5p5p9bMAwIhAMd9bGqyR9X8\n"
    "k3v1WkV0w7L5w3xP4f8N2bGmHy0xPwZc\n"
    "-----END RSA PRIVATE KEY-----\n";

int main(void) {
    /* Print a slice of the key. Without this, gcc -O2 replaces strlen()
     * with a compile-time constant and elides the string from .rodata,
     * defeating the whole point of the fixture. Printing forces the
     * bytes to remain in the binary. */
    size_t n = strlen(hardcoded_signing_key);
    printf("Signing key loaded (%zu bytes):\n%.60s...\n", n, hardcoded_signing_key);
    return 0;
}
