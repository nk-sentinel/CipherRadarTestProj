package benchmark

import (
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh"
)

// EXPECTED: ChaCha20-Poly1305 | AEAD | 256 | info | quantum-safe
func EncryptChaCha20(key, plaintext, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

// EXPECTED: Curve25519 | - | 256 | low | quantum-vulnerable
func GenerateNaClBoxKeys() (*[32]byte, *[32]byte, error) {
	pub, priv, err := box.GenerateKey(nil)
	return pub, priv, err
}

// EXPECTED: XSalsa20-Poly1305 | AEAD | 256 | info | quantum-safe
func SealSecretBox(key *[32]byte, message []byte, nonce *[24]byte) []byte {
	return secretbox.Seal(nil, message, nonce, key)
}

// EXPECTED: Argon2id | - | 256 | info | quantum-safe
func DeriveKeyArgon2(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// EXPECTED: bcrypt | - | - | info | quantum-safe
func HashPasswordBcrypt(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, 12)
}

// EXPECTED: bcrypt | - | - | medium | quantum-safe
func HashPasswordBcryptWeak(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, 4) // BAD: low cost factor
}

// EXPECTED: scrypt | - | 256 | info | quantum-safe
func DeriveKeyScrypt(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, 32)
}

// EXPECTED: HKDF-SHA256 | - | - | info | quantum-safe
func DeriveKeyHKDF(secret, salt, info []byte) []byte {
	reader := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, 32)
	reader.Read(key)
	return key
}

// EXPECTED: SSH | - | - | info | quantum-vulnerable
func ParseSSHKey(pemBytes []byte) (interface{}, error) {
	key, err := ssh.ParseRawPrivateKey(pemBytes)
	return key, err
}
