// Web Crypto API patterns (browser/Deno/Node 15+)

// EXPECTED: AES | GCM | 256 | info | quantum-safe
async function generateAESGCMKey() {
    return await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

// EXPECTED: RSA | OAEP | 2048 | medium | quantum-vulnerable
async function generateRSAOAEPKey() {
    return await crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        ['encrypt', 'decrypt']
    );
}

// EXPECTED: ECDSA | - | 256 | low | quantum-vulnerable
async function generateECDSAKey() {
    return await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );
}

// EXPECTED: SHA-256 | - | - | info | quantum-safe
async function digestSHA256(data) {
    return await crypto.subtle.digest('SHA-256', data);
}

// EXPECTED: SHA-1 | - | - | medium | quantum-vulnerable
async function digestSHA1(data) {
    return await crypto.subtle.digest('SHA-1', data); // DEPRECATED
}

// EXPECTED: PBKDF2 | - | - | critical | quantum-safe
async function deriveKeyPBKDF2Weak(password, salt) {
    const keyMaterial = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
    return await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: salt, iterations: 100, hash: 'SHA-256' }, // BAD: 100 iterations
        keyMaterial, 256
    );
}

module.exports = { generateAESGCMKey, generateRSAOAEPKey, generateECDSAKey, digestSHA256, digestSHA1, deriveKeyPBKDF2Weak };
