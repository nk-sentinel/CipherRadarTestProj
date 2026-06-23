<?php
/**
 * RSA key generation via openssl_pkey_new with an explicit private_key_bits.
 * Exercises the PHP private_key_bits key-size capture.
 */

// EXPECTED: RSA | - | 4096 | medium | quantum-vulnerable
$key = openssl_pkey_new([
    'private_key_bits' => 4096,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
]);
