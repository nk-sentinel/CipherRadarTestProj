/**
 * node-forge crypto patterns.
 */
const forge = require('node-forge');

// BAD: MD5 digest
function hashMD5(data) {
    const md = forge.md.md5.create();
    md.update(data);
    return md.digest().toHex();
}

// BAD: SHA-1 digest
function hashSHA1(data) {
    const md = forge.md.sha1.create();
    md.update(data);
    return md.digest().toHex();
}

// GOOD: SHA-256
function hashSHA256(data) {
    const md = forge.md.sha256.create();
    md.update(data);
    return md.digest().toHex();
}

// GOOD: SHA-512
function hashSHA512(data) {
    const md = forge.md.sha512.create();
    md.update(data);
    return md.digest().toHex();
}

// AES-CBC encryption via forge
function encryptAES(key, data) {
    const cipher = forge.cipher.createCipher('AES-CBC', key);
    cipher.start({ iv: forge.random.getBytesSync(16) });
    cipher.update(forge.util.createBuffer(data));
    cipher.finish();
    return cipher.output.toHex();
}

// QUANTUM-VULNERABLE: RSA-2048
function generateRSAKeyPair() {
    return forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });
}

// BAD: RSA-1024 (too small)
function generateWeakRSA() {
    return forge.pki.rsa.generateKeyPair({ bits: 1024 });
}

// HMAC-SHA256
function computeHMAC(key, data) {
    const hmac = forge.hmac.create();
    hmac.start('sha256', key);
    hmac.update(data);
    return hmac.digest().toHex();
}

module.exports = {
    hashMD5, hashSHA1, hashSHA256, hashSHA512,
    encryptAES, generateRSAKeyPair, generateWeakRSA, computeHMAC
};
