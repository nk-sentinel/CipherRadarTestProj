// Swift crypto benchmark fixture for CipherRadar recall measurement.
//
// Scanner claims (docs 03 §2): CommonCrypto, CryptoKit, Security framework.
// EXPECTED annotations placed where a claimed framework should trigger.

import CryptoKit
import CommonCrypto
import Foundation
import Security

// --- Strong AEAD: AES-GCM via CryptoKit (modelled AES.GCM.seal) ---
// EXPECTED: AES-GCM | gcm | 256 | info | quantum-vulnerable
func aesGcmSeal(key: SymmetricKey, data: Data) throws -> Data {
    let sealed = try AES.GCM.seal(data, using: key)
    return sealed.combined!
}

// --- Strong AEAD: ChaChaPoly via CryptoKit (modelled) ---
// EXPECTED: ChaChaPoly | gcm |  | info | quantum-vulnerable
func chachaSeal(key: SymmetricKey, data: Data) throws -> Data {
    let sealed = try ChaChaPoly.seal(data, using: key)
    return sealed.combined
}

// --- Weak cipher: DES via CommonCrypto CCCrypt with kCCAlgorithmDES ---
// EXPECTED: DES |  |  | high | broken
func desEncrypt(key: Data, data: Data, out: UnsafeMutableRawPointer) {
    var moved = 0
    CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmDES),
            CCOptions(kCCOptionECBMode), (key as NSData).bytes, key.count,
            nil, (data as NSData).bytes, data.count, out, data.count, &moved)
}

// --- Weak cipher: RC4 via CommonCrypto CCCrypt with kCCAlgorithmRC4 ---
// EXPECTED: RC4 |  |  | high | broken
func rc4Encrypt(key: Data, data: Data, out: UnsafeMutableRawPointer) {
    var moved = 0
    CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmRC4),
            CCOptions(0), (key as NSData).bytes, key.count,
            nil, (data as NSData).bytes, data.count, out, data.count, &moved)
}

// --- MD5 via CommonCrypto CC_MD5 (modelled) ---
// EXPECTED: MD5 |  |  | high | broken
func md5Hash(data: Data, out: UnsafeMutablePointer<UInt8>) {
    CC_MD5((data as NSData).bytes, CC_LONG(data.count), out)
}

// --- SHA-256 via CryptoKit SHA256.hash (modelled) ---
// EXPECTED: SHA-256 |  |  | info | quantum-safe
func sha256Hash(data: Data) -> SHA256.Digest {
    return SHA256.hash(data: data)
}

// --- RSA keygen via Security SecKeyCreateRandomKey (modelled) ---
// EXPECTED: RSA | pke | 2048 | info | quantum-vulnerable
func generateRSAKey() -> SecKey? {
    let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                kSecAttrKeySizeInBits as String: 2048]
    var error: Unmanaged<CFError>?
    return SecKeyCreateRandomKey(attrs as CFDictionary, &error)
}

// --- ECDSA signing keygen via CryptoKit P256.Signing (modelled) ---
// EXPECTED: P256-Signing | signature |  | info | quantum-vulnerable
func generateP256() -> P256.Signing.PrivateKey {
    return P256.Signing.PrivateKey()
}

// --- KDF: PBKDF2 via CommonCrypto CCKeyDerivationPBKDF (modelled) ---
// EXPECTED: PBKDF2 | kdf |  | info | quantum-safe
func deriveKey(password: String, salt: Data, out: UnsafeMutablePointer<UInt8>) {
    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, password.count,
                         (salt as NSData).bytes, salt.count,
                         CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 100000, out, 32)
}

// --- TLS protocol via Network.framework TLS options (protocol usage) ---
// EXPECTED: TLS | tls |  | info | quantum-vulnerable
func configureTLS() {
    let options = NWProtocolTLS.Options()
    sec_protocol_options_set_min_tls_protocol_version(
        options.securityProtocolOptions, .TLSv12)
}
