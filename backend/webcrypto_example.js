/**
 * Web Crypto API patterns (browser-side crypto).
 */

// GOOD: AES-GCM via Web Crypto
async function encryptWebCrypto(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        data
    );
    return { iv, encrypted };
}

// GOOD: SHA-256 digest via Web Crypto
async function digestSHA256(data) {
    return await crypto.subtle.digest('SHA-256', data);
}

// QUANTUM-VULNERABLE: RSA-OAEP key generation
async function generateRSAKey() {
    return await crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
    );
}

// GOOD: AES-CBC key generation
async function generateAESKey() {
    return await crypto.subtle.generateKey(
        { name: 'AES-CBC', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

// QUANTUM-VULNERABLE: ECDSA P-256
async function generateECDSAKey() {
    return await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );
}
