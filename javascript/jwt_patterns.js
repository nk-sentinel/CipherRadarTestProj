const jwt = require('jsonwebtoken');

const JWT_SECRET = 'my-hardcoded-secret-key-12345'; // BAD: hardcoded secret

// EXPECTED: HMAC-SHA256 | - | - | low | quantum-safe
function signHS256(payload) {
    return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
}

// EXPECTED: HMAC-SHA384 | - | - | low | quantum-safe
function signHS384(payload) {
    return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS384' });
}

// EXPECTED: RSA-SHA256 | - | - | medium | quantum-vulnerable
function signRS256(payload, privateKey) {
    return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
}

// EXPECTED: ECDSA-SHA256 | - | - | medium | quantum-vulnerable
function signES256(payload, privateKey) {
    return jwt.sign(payload, privateKey, { algorithm: 'ES256' });
}

// EXPECTED: none | - | - | critical | broken
function verifyNone(token) {
    return jwt.verify(token, '', { algorithms: ['none'] }); // CRITICAL: alg:none
}

// EXPECTED: RSA-SHA256 | - | - | info | quantum-vulnerable
function verifyRS256(token, publicKey) {
    return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}

module.exports = { signHS256, signHS384, signRS256, signES256, verifyNone, verifyRS256 };
