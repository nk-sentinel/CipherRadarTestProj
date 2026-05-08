/**
 * Crypto utilities — mix of secure and insecure patterns.
 * NOTE: JS scanner not yet implemented (M3). These should be skipped cleanly.
 */
const crypto = require('crypto');

// BAD: MD5
function hashMD5(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}

// GOOD: SHA-256
function hashSHA256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

// BAD: DES
function encryptDES(key, data) {
    const cipher = crypto.createCipheriv('des-ecb', key, null);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// GOOD: AES-256-GCM
function encryptAES(key, data) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    return { iv, encrypted, tag: cipher.getAuthTag() };
}

// QUANTUM-VULNERABLE: RSA-2048
function generateRSAKey() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
}

module.exports = { hashMD5, hashSHA256, encryptDES, encryptAES, generateRSAKey };
