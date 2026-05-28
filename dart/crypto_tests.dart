// Dart crypto benchmark fixture for CipherRadar recall measurement.
//
// Scanner claims (docs 03 §2): package:crypto, package:cryptography,
// pointycastle. (Implementation also covers package:encrypt.)
// EXPECTED annotations placed where a claimed library should trigger.

import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/export.dart';
import 'package:encrypt/encrypt.dart';

// --- Strong AEAD: AES-GCM via package:cryptography (docs claim it) ---
// EXPECTED: AES-256-GCM | gcm | 256 | info | quantum-vulnerable
final aesGcm = AesGcm.with256bits();

// --- Strong AEAD via package:encrypt AES (modelled by impl) ---
// EXPECTED: AES | gcm | 256 | info | quantum-vulnerable
final encrypter = Encrypter(AES(Key.fromLength(32), mode: AESMode.gcm));

// --- Weak cipher: DES via pointycastle (modelled) ---
// EXPECTED: DES |  |  | high | broken
final desEngine = DESEngine();

// --- Weak stream cipher: RC4 via pointycastle (modelled) ---
// EXPECTED: RC4 |  |  | high | broken
final rc4Engine = RC4Engine();

// --- MD5 via package:crypto (modelled) ---
// EXPECTED: MD5 |  |  | high | broken
final md5Digest = md5.convert(utf8.encode('data'));

// --- SHA-256 via package:crypto (modelled) ---
// EXPECTED: SHA-256 |  |  | info | quantum-safe
final sha256Digest = sha256.convert(utf8.encode('data'));

// --- RSA keygen via pointycastle (modelled — RSAEngine; keygen via generator) ---
// EXPECTED: RSA | pke | 2048 | info | quantum-vulnerable
final rsaGen = RSAKeyGenerator()
  ..init(ParametersWithRandom(
      RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 64),
      FortunaRandom()));

// --- ECDSA keygen via pointycastle (docs claim pointycastle EC) ---
// EXPECTED: ECDSA | signature |  | info | quantum-vulnerable
final ecGen = ECKeyGenerator()
  ..init(ParametersWithRandom(
      ECKeyGeneratorParameters(ECCurve_secp256r1()), FortunaRandom()));

// --- KDF: PBKDF2 via pointycastle (modelled) ---
// EXPECTED: PBKDF2 | kdf |  | info | quantum-safe
final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));

// --- KDF: scrypt via pointycastle (docs claim pointycastle) ---
// EXPECTED: scrypt | kdf |  | info | quantum-safe
final scrypt = Scrypt()..init(ScryptParameters(16384, 8, 1, 32, utf8.encode('salt')));

// --- TLS via package:cryptography Hkdf / handshake helpers (protocol usage) ---
// EXPECTED: TLS | tls |  | info | quantum-vulnerable
final tlsSecret = SecureSocket; // dart:io SecureSocket — TLS endpoint indicator
