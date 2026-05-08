package benchmark

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.net.ssl.SSLContext

class CryptoTests {

    // EXPECTED: AES | GCM | 256 | info | quantum-safe
    fun encryptAESGCM(key: ByteArray, data: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        return cipher.doFinal(data)
    }

    // EXPECTED: AES | CBC | 256 | low | quantum-safe
    fun encryptAESCBC(key: ByteArray, data: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    // EXPECTED: AES | ECB | - | high | quantum-safe
    fun encryptAESECB(key: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding") // BAD: ECB mode
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(data)
    }

    // EXPECTED: DES | ECB | 56 | critical | broken
    fun encryptDES(key: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding") // BAD
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "DES"))
        return cipher.doFinal(data)
    }

    // EXPECTED: 3DES | CBC | 168 | high | quantum-safe
    fun encryptTripleDES(key: ByteArray, data: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding") // DEPRECATED
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "DESede"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    // EXPECTED: MD5 | - | - | high | broken
    fun hashMD5(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("MD5").digest(data) // BAD
    }

    // EXPECTED: SHA-1 | - | - | medium | quantum-vulnerable
    fun hashSHA1(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-1").digest(data) // DEPRECATED
    }

    // EXPECTED: SHA-256 | - | - | info | quantum-safe
    fun hashSHA256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    // EXPECTED: SHA-512 | - | - | info | quantum-safe
    fun hashSHA512(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-512").digest(data)
    }

    // EXPECTED: RSA | - | 2048 | medium | quantum-vulnerable
    fun generateRSA(): java.security.KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        return kpg.generateKeyPair()
    }

    // EXPECTED: ECDSA | - | 256 | low | quantum-vulnerable
    fun generateEC(): java.security.KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        return kpg.generateKeyPair()
    }

    // EXPECTED: HMAC-SHA256 | - | - | info | quantum-safe
    fun computeHMAC(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    // EXPECTED: SHA256withRSA | - | - | low | quantum-vulnerable
    fun signRSA(data: ByteArray, privateKey: java.security.PrivateKey): ByteArray {
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(privateKey)
        sig.update(data)
        return sig.sign()
    }

    // EXPECTED: AES | - | 256 | info | quantum-safe
    fun generateAESKey(): javax.crypto.SecretKey {
        val kg = KeyGenerator.getInstance("AES")
        kg.init(256)
        return kg.generateKey()
    }

    // EXPECTED: PBKDF2 | - | - | critical | quantum-safe
    fun deriveKeyWeak(password: CharArray, salt: ByteArray): javax.crypto.SecretKey {
        val spec = PBEKeySpec(password, salt, 100, 256) // BAD: 100 iterations
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return factory.generateSecret(spec)
    }

    // EXPECTED: TLS | 1.0 | - | critical | quantum-vulnerable
    fun weakTLS(): SSLContext {
        return SSLContext.getInstance("TLSv1") // BAD
    }

    // EXPECTED: TLS | 1.3 | - | info | quantum-safe
    fun strongTLS(): SSLContext {
        return SSLContext.getInstance("TLSv1.3")
    }

    // EXPECTED: AES | - | - | critical | quantum-safe
    fun hardcodedKey(): ByteArray {
        val key = "hardcoded-secret".toByteArray() // BAD: hardcoded key
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(byteArrayOf())
    }
}
