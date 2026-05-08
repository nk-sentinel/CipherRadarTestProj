<?php
/**
 * PHP Crypto Test Patterns for CipherRadar Benchmark
 */

// EXPECTED: AES | GCM | 256 | info | quantum-safe
function encryptAESGCM(string $data, string $key): array {
    $iv = random_bytes(12);
    $tag = '';
    $ciphertext = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return ['ciphertext' => $ciphertext, 'iv' => $iv, 'tag' => $tag];
}

// EXPECTED: AES | CBC | 256 | low | quantum-safe
function encryptAESCBC(string $data, string $key): string {
    $iv = random_bytes(16);
    return openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
}

// EXPECTED: AES | ECB | 256 | high | quantum-safe
function encryptAESECB(string $data, string $key): string {
    return openssl_encrypt($data, 'aes-256-ecb', $key, OPENSSL_RAW_DATA); // BAD: ECB mode
}

// EXPECTED: DES | ECB | 56 | critical | broken
function encryptDES(string $data, string $key): string {
    return openssl_encrypt($data, 'des-ecb', $key, OPENSSL_RAW_DATA); // BAD
}

// EXPECTED: RC4 | - | - | critical | broken
function encryptRC4(string $data, string $key): string {
    return openssl_encrypt($data, 'rc4', $key, OPENSSL_RAW_DATA); // BAD
}

// EXPECTED: 3DES | CBC | 168 | high | quantum-safe
function encrypt3DES(string $data, string $key): string {
    $iv = random_bytes(8);
    return openssl_encrypt($data, 'des-ede3-cbc', $key, OPENSSL_RAW_DATA, $iv); // DEPRECATED
}

// EXPECTED: MD5 | - | - | high | broken
function hashMD5(string $data): string {
    return hash('md5', $data); // BAD
}

// EXPECTED: SHA-1 | - | - | medium | quantum-vulnerable
function hashSHA1(string $data): string {
    return hash('sha1', $data); // DEPRECATED
}

// EXPECTED: SHA-256 | - | - | info | quantum-safe
function hashSHA256(string $data): string {
    return hash('sha256', $data);
}

// EXPECTED: SHA-512 | - | - | info | quantum-safe
function hashSHA512(string $data): string {
    return hash('sha512', $data);
}

// EXPECTED: HMAC-SHA256 | - | - | info | quantum-safe
function hmacSHA256(string $key, string $data): string {
    return hash_hmac('sha256', $data, $key);
}

// EXPECTED: PBKDF2 | - | - | critical | quantum-safe
function deriveKeyWeak(string $password, string $salt): string {
    return hash_pbkdf2('sha256', $password, $salt, 100, 32, true); // BAD: 100 iterations
}

// EXPECTED: PBKDF2 | - | - | info | quantum-safe
function deriveKeyStrong(string $password, string $salt): string {
    return hash_pbkdf2('sha256', $password, $salt, 600000, 32, true); // GOOD
}

// EXPECTED: bcrypt | - | - | info | quantum-safe
function hashPasswordBcrypt(string $password): string {
    return password_hash($password, PASSWORD_BCRYPT);
}

// EXPECTED: Argon2id | - | - | info | quantum-safe
function hashPasswordArgon2(string $password): string {
    return password_hash($password, PASSWORD_ARGON2ID);
}

// EXPECTED: XSalsa20-Poly1305 | AEAD | - | info | quantum-safe
function encryptSodiumSecretbox(string $message, string $nonce, string $key): string {
    return sodium_crypto_secretbox($message, $nonce, $key);
}

// EXPECTED: X25519 | - | 256 | low | quantum-vulnerable
function generateSodiumBoxKeypair(): string {
    return sodium_crypto_box_keypair();
}

// EXPECTED: Ed25519 | - | 256 | low | quantum-vulnerable
function generateSodiumSignKeypair(): string {
    return sodium_crypto_sign_keypair();
}

// EXPECTED: DES | ECB | 56 | critical | broken
function encryptMcryptDES(string $key, string $data): string {
    return mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB); // BAD: deprecated API
}
