/**
 * Test cases for CBOM inventory OpenGrep rules (JavaScript).
 * Cross-statement patterns for crypto supply chain tracking.
 */
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// ── Rule 3: KDF → Cipher Chain ──
// EXPECTED: CBOM links PBKDF2 derivation to cipher usage
function kdfToCipherChain(password, salt) {
    const key = crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    return cipher;
}

// ── Rule 3 variant: Scrypt → Cipher ──
function scryptToCipher(password, salt) {
    const key = crypto.scryptSync(password, salt, 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return cipher;
}

// ── Rule 6: Config-Driven Algorithm ──
// EXPECTED: CBOM tracks algorithm from environment
function configDrivenCipher() {
    const algo = process.env.CIPHER_ALGORITHM;
    if (algo) {
        const key = crypto.randomBytes(32);
        return crypto.createCipheriv(algo, key, crypto.randomBytes(16));
    }
}

function configDrivenHash() {
    const algo = process.env.HASH_ALGORITHM;
    if (algo) {
        return crypto.createHash(algo).update('data').digest('hex');
    }
}

module.exports = { kdfToCipherChain, scryptToCipher, configDrivenCipher, configDrivenHash };
