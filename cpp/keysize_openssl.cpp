// OpenSSL key-size capture fixtures where the bit count is not the first call
// argument: RSA_generate_key_ex (bits = arg 1) and AES_set_encrypt_key
// (bits = arg 1).
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/bn.h>

// EXPECTED: RSA | - | 3072 | medium | quantum-vulnerable
void gen_rsa(RSA *rsa, BIGNUM *e) {
    RSA_generate_key_ex(rsa, 3072, e, NULL);
}

// EXPECTED: AES | - | 256 | info | quantum-safe
void set_aes(const unsigned char *userKey, AES_KEY *enc) {
    AES_set_encrypt_key(userKey, 256, enc);
}
