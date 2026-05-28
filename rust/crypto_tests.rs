// Rust crypto benchmark fixture for CipherRadar recall measurement.
//
// Scanner claims (docs 03 §2): ring, rustls, openssl crate, aes, rsa crates.
// EXPECTED annotations are placed only where at least one of those modelled
// libraries should plausibly trigger a finding.

use ring::digest;
use ring::aead;
use ring::pbkdf2;
use ring::signature;
use rustls::ClientConfig;
use openssl::symm::Cipher;
use openssl::hash::{Hasher, MessageDigest};
use openssl::rsa::Rsa;
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead as _;
use rsa::RsaPrivateKey;

// --- Strong AEAD: ring AES-256-GCM (UnboundKey path — modelled) ---
// EXPECTED: AES-256-GCM | gcm | 256 | info | quantum-vulnerable
fn ring_aes_gcm(key_bytes: &[u8]) {
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes).unwrap();
    let _key = aead::LessSafeKey::new(unbound);
}

// --- Strong AEAD via RustCrypto aes-gcm crate (docs claim "aes" crate) ---
// EXPECTED: AES-256-GCM | gcm | 256 | info | quantum-vulnerable
fn rustcrypto_aes_gcm(key_bytes: &[u8], nonce: &[u8], data: &[u8]) {
    let cipher = Aes256Gcm::new(key_bytes.into());
    let _ct = cipher.encrypt(nonce.into(), data).unwrap();
}

// --- Weak cipher: DES-CBC via openssl crate (modelled symm) ---
// EXPECTED: DES-CBC | cbc |  | high | broken
fn openssl_des(_key: &[u8], _iv: &[u8]) {
    let _cipher = Cipher::des_cbc();
}

// --- Weak stream cipher: RC4 via openssl crate (modelled symm) ---
// EXPECTED: RC4 |  |  | high | broken
fn openssl_rc4() {
    let _cipher = Cipher::rc4();
}

// --- MD5 via openssl crate (modelled hash) ---
// EXPECTED: MD5 |  |  | high | broken
fn openssl_md5() {
    let _h = Hasher::new(MessageDigest::md5()).unwrap();
}

// --- SHA-256 via ring::digest (modelled) ---
// EXPECTED: SHA-256 |  |  | info | quantum-safe
fn ring_sha256(data: &[u8]) {
    let _d = digest::digest(&digest::SHA256, data);
}

// --- RSA keygen via openssl crate (modelled) ---
// EXPECTED: RSA | pke | 2048 | info | quantum-vulnerable
fn openssl_rsa_keygen() {
    let _rsa = Rsa::generate(2048).unwrap();
}

// --- RSA keygen via RustCrypto rsa crate (docs claim "rsa" crate) ---
// EXPECTED: RSA | pke | 2048 | info | quantum-vulnerable
fn rustcrypto_rsa_keygen() {
    let mut rng = rand::thread_rng();
    let _priv = RsaPrivateKey::new(&mut rng, 2048).unwrap();
}

// --- ECDSA signature keypair via ring::signature (modelled) ---
// EXPECTED: ECDSA-P256-SHA256 | signature |  | info | quantum-vulnerable
fn ring_ecdsa(pkcs8: &[u8]) {
    let _kp = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8,
        &ring::rand::SystemRandom::new()).unwrap();
}

// --- KDF: PBKDF2 via ring::pbkdf2 (modelled) ---
// EXPECTED: PBKDF2 | kdf |  | info | quantum-safe
fn ring_pbkdf2(pass: &[u8], salt: &[u8]) {
    let mut out = [0u8; 32];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(100_000).unwrap(), salt, pass, &mut out);
}

// --- TLS protocol: rustls client config (modelled) ---
// EXPECTED: TLS | tls |  | info | quantum-vulnerable
fn rustls_tls() {
    let _cfg = ClientConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();
}
