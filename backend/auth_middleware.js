/**
 * Authentication middleware with JWT and session handling.
 */
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = 'hardcoded-jwt-secret-not-secure';

// BAD: alg:none allows forged tokens
function verifyTokenUnsafe(token) {
    return jwt.verify(token, '', { algorithms: ['none'] });
}

// GOOD: HS256 with proper verification
function verifyToken(token) {
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
}

// Sign with RS256
function signTokenRS256(payload, privateKey) {
    return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
}

// Sign with HS384
function signTokenHS384(payload) {
    return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS384' });
}

// Session ID generation with SHA-256
function generateSessionId() {
    return crypto.createHash('sha256')
        .update(crypto.randomBytes(32))
        .digest('hex');
}

// BAD: MD5 for session fingerprint
function fingerprintSession(userAgent, ip) {
    return crypto.createHash('md5')
        .update(userAgent + ip)
        .digest('hex');
}

// HMAC for CSRF token
function generateCSRFToken(sessionId) {
    return crypto.createHmac('sha256', JWT_SECRET)
        .update(sessionId)
        .digest('hex');
}

module.exports = {
    verifyTokenUnsafe, verifyToken, signTokenRS256,
    signTokenHS384, generateSessionId, fingerprintSession, generateCSRFToken
};
