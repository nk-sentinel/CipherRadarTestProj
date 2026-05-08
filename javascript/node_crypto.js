const crypto = require('crypto');

// EXPECTED: MD5 | - | - | high | broken
function hashMD5(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}

// EXPECTED: SHA-1 | - | - | medium | quantum-vulnerable
function hashSHA1(data) {
    return crypto.createHash('sha1').update(data).digest('hex');
}

// EXPECTED: SHA-256 | - | - | info | quantum-safe
function hashSHA256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

// EXPECTED: SHA-512 | - | - | info | quantum-safe
function hashSHA512(data) {
    return crypto.createHash('sha512').update(data).digest('hex');
}

// EXPECTED: HMAC-SHA256 | - | - | info | quantum-safe
function hmacSHA256(key, data) {
    return crypto.createHmac('sha256', key).update(data).digest('hex');
}

// EXPECTED: AES | GCM | 256 | info | quantum-safe
function encryptAESGCM(key, plaintext) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { iv, encrypted, tag };
}

// EXPECTED: AES | CBC | 256 | low | quantum-safe
function encryptAESCBC(key, plaintext) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

// EXPECTED: DES | ECB | 56 | critical | broken
function encryptDES(key, data) {
    const cipher = crypto.createCipheriv('des-ecb', key, null);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

// EXPECTED: RC4 | - | - | critical | broken
function encryptRC4(key, data) {
    const cipher = crypto.createCipheriv('rc4', key, null);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

// EXPECTED: RSA | - | 2048 | medium | quantum-vulnerable
function generateRSA2048() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
}

// EXPECTED: ECDSA | - | 256 | low | quantum-vulnerable
function generateECDSA() {
    return crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
}

// EXPECTED: PBKDF2 | - | - | critical | quantum-safe
function deriveKeyPBKDF2Weak(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100, 32, 'sha256'); // BAD: 100 iterations
}

// EXPECTED: PBKDF2 | - | - | info | quantum-safe
function deriveKeyPBKDF2Strong(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 600000, 32, 'sha256'); // GOOD
}

// EXPECTED: scrypt | - | - | info | quantum-safe
function deriveKeyScrypt(password, salt) {
    return crypto.scryptSync(password, salt, 32);
}

// EXPECTED: CSPRNG | - | - | info | quantum-safe
function generateRandomBytes() {
    return crypto.randomBytes(32);
}

module.exports = {
    hashMD5, hashSHA1, hashSHA256, hashSHA512,
    hmacSHA256, encryptAESGCM, encryptAESCBC,
    encryptDES, encryptRC4, generateRSA2048, generateECDSA,
    deriveKeyPBKDF2Weak, deriveKeyPBKDF2Strong, deriveKeyScrypt,
    generateRandomBytes,
};
