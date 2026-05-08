/**
 * TypeScript encryption service with various crypto patterns.
 */
import * as crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 12;

interface EncryptedData {
    iv: string;
    ciphertext: string;
    tag: string;
}

// GOOD: AES-256-GCM (algorithm resolved via constprop)
export function encrypt(key: Buffer, plaintext: string): EncryptedData {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return {
        iv: iv.toString('hex'),
        ciphertext: encrypted.toString('hex'),
        tag: (cipher as any).getAuthTag().toString('hex'),
    };
}

// BAD: DES-ECB (broken algorithm + insecure mode)
export function encryptLegacy(key: Buffer, data: string): string {
    const cipher = crypto.createCipheriv('des-ecb', key.slice(0, 8), null);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// BAD: RC4 (broken stream cipher)
export function encryptRC4(key: Buffer, data: string): string {
    const cipher = crypto.createCipheriv('rc4', key, '');
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// GOOD: SHA-512 hashing
export function hashData(data: string): string {
    return crypto.createHash('sha512').update(data).digest('hex');
}

// BAD: SHA-1 for integrity
export function legacyHash(data: string): string {
    return crypto.createHash('sha1').update(data).digest('hex');
}

// QUANTUM-VULNERABLE: RSA-4096 key generation
export function generateKeyPair(): crypto.KeyPairSyncResult<string, string> {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
}

// QUANTUM-VULNERABLE: ECDH
export function performKeyExchange(): crypto.ECDH {
    return crypto.createECDH('secp384r1');
}

// PBKDF2 for password hashing
export function deriveKey(password: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256');
}

// Scrypt for password hashing
export function deriveKeyScrypt(password: string, salt: Buffer): Buffer {
    return crypto.scryptSync(password, salt, 32);
}
