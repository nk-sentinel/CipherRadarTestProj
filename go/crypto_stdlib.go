package benchmark

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"io"
)

// EXPECTED: AES | GCM | 256 | info | quantum-safe
func EncryptAESGCM(key, plaintext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

// EXPECTED: AES | CBC | 256 | low | quantum-safe
func EncryptAESCBC(key, plaintext, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// EXPECTED: AES | CTR | 256 | info | quantum-safe
func EncryptAESCTR(key, plaintext, iv []byte) []byte {
	block, _ := aes.NewCipher(key)
	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

// EXPECTED: AES | OFB | 256 | low | quantum-safe
func EncryptAESOFB(key, plaintext, iv []byte) []byte {
	block, _ := aes.NewCipher(key)
	stream := cipher.NewOFB(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

// EXPECTED: DES | - | 56 | critical | broken
func EncryptDES(key, data []byte) {
	block, _ := des.NewCipher(key)
	_ = block
}

// EXPECTED: 3DES | - | 168 | high | quantum-safe
func EncryptTripleDES(key, data []byte) {
	block, _ := des.NewTripleDESCipher(key)
	_ = block
}

// EXPECTED: RC4 | - | - | critical | broken
func EncryptRC4(key []byte) {
	c, _ := rc4.NewCipher(key)
	_ = c
}

// EXPECTED: MD5 | - | - | high | broken
func HashMD5(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

// EXPECTED: MD5 | - | - | high | broken
func HashMD5Sum(data []byte) [16]byte {
	return md5.Sum(data)
}

// EXPECTED: SHA-1 | - | - | medium | quantum-vulnerable
func HashSHA1(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

// EXPECTED: SHA-256 | - | - | info | quantum-safe
func HashSHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// EXPECTED: SHA-512 | - | - | info | quantum-safe
func HashSHA512(data []byte) [64]byte {
	return sha512.Sum512(data)
}

// EXPECTED: SHA-384 | - | - | info | quantum-safe
func HashSHA384(data []byte) []byte {
	h := sha512.New384()
	h.Write(data)
	return h.Sum(nil)
}

// EXPECTED: HMAC-SHA256 | - | - | info | quantum-safe
func ComputeHMAC(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// EXPECTED: RSA | - | 2048 | medium | quantum-vulnerable
func GenerateRSA2048() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// EXPECTED: RSA | - | 4096 | low | quantum-vulnerable
func GenerateRSA4096() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

// EXPECTED: RSA | PKCS1v15 | - | medium | quantum-vulnerable
func SignPKCS1v15(priv *rsa.PrivateKey, hash []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, priv, 0, hash)
}

// EXPECTED: RSA | OAEP | - | low | quantum-vulnerable
func EncryptOAEP(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
}

// EXPECTED: ECDSA | - | 256 | low | quantum-vulnerable
func GenerateECDSAP256() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// EXPECTED: ECDSA | - | 384 | low | quantum-vulnerable
func GenerateECDSAP384() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

// EXPECTED: Ed25519 | - | 256 | low | quantum-vulnerable
func GenerateEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// EXPECTED: TLS | 1.0 | - | critical | quantum-vulnerable
func WeakTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
	}
}

// EXPECTED: TLS | 1.3 | - | info | quantum-safe
func StrongTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
}

// EXPECTED: TLS | 1.1 | - | high | quantum-vulnerable
func DeprecatedTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS11,
	}
}

// Suppress unused import warnings
var _ = io.Discard
