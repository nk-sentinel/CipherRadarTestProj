// C++ crypto benchmark fixture for CipherRadar recall measurement.
//
// Scanner claims (docs 03 §2): OpenSSL, libsodium, mbedTLS, WolfSSL, GnuTLS.
// EXPECTED annotations placed where a claimed library should trigger.
// (Note: the EVP_* detectors emit a finding on the init call but do not
//  resolve the EVP_aes_*_gcm cipher argument, so mode is best-effort.)

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <sodium.h>

// --- Strong AEAD: AES-256-GCM via OpenSSL EVP (EVP_EncryptInit modelled) ---
// EXPECTED: AES-256-GCM | gcm | 256 | info | quantum-vulnerable
void aes_gcm_encrypt(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv) {
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
}

// --- Strong AEAD via libsodium (modelled crypto_aead) ---
// EXPECTED: AES-256-GCM | gcm | 256 | info | quantum-vulnerable
void sodium_aead(unsigned char *c, const unsigned char *m, const unsigned char *npub, const unsigned char *k) {
    unsigned long long clen;
    crypto_aead_aes256gcm_encrypt(c, &clen, m, 64, NULL, 0, NULL, npub, k);
}

// --- Weak cipher: DES via OpenSSL (modelled DES_set_key) ---
// EXPECTED: DES |  |  | high | broken
void des_setup(const_DES_cblock *key, DES_key_schedule *ks) {
    DES_set_key(key, ks);
}

// --- Weak stream cipher: RC4 via OpenSSL (modelled RC4_set_key) ---
// EXPECTED: RC4 |  |  | high | broken
void rc4_setup(RC4_KEY *k, const unsigned char *key) {
    RC4_set_key(k, 16, key);
}

// --- MD5 via OpenSSL (modelled) ---
// EXPECTED: MD5 |  |  | high | broken
void md5_hash(const unsigned char *d, size_t n, unsigned char *out) {
    MD5(d, n, out);
}

// --- SHA-256 via OpenSSL (modelled) ---
// EXPECTED: SHA-256 |  |  | info | quantum-safe
void sha256_hash(const unsigned char *d, size_t n, unsigned char *out) {
    SHA256(d, n, out);
}

// --- RSA keygen via OpenSSL (modelled RSA_generate_key) ---
// EXPECTED: RSA-2048 | pke | 2048 | info | quantum-vulnerable
void rsa_keygen() {
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
}

// --- KDF: PBKDF2 via OpenSSL PKCS5_PBKDF2_HMAC (docs claim OpenSSL) ---
// EXPECTED: PBKDF2 | kdf |  | info | quantum-safe
void pbkdf2_derive(const char *pass, const unsigned char *salt, unsigned char *out) {
    PKCS5_PBKDF2_HMAC(pass, -1, salt, 16, 100000, EVP_sha256(), 32, out);
}

// --- KDF: Argon2 via libsodium crypto_pwhash (modelled) ---
// EXPECTED: Argon2 | kdf |  | info | quantum-safe
void argon2_hash(char *out, const char *pass) {
    crypto_pwhash_str(out, pass, 8, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
}

// --- TLS protocol via OpenSSL SSL_CTX_new (modelled) ---
// EXPECTED: TLS | tls |  | info | quantum-vulnerable
void tls_setup() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
}
