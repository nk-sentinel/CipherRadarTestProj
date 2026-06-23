package benchmark

import java.security.KeyPairGenerator
import javax.crypto.KeyGenerator
import java.security.SecureRandom

// Two-argument key-generator init using the standard JCA ordering
// (keysize first, SecureRandom second). Exercises the size-first capture path.
class KeySizeTwoArg {
    // EXPECTED: RSA | - | 3072 | medium | quantum-vulnerable
    fun generateRSA(): java.security.KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(3072, SecureRandom())
        return kpg.generateKeyPair()
    }

    // EXPECTED: AES | - | 192 | info | quantum-safe
    fun generateAES(): javax.crypto.SecretKey {
        val kg = KeyGenerator.getInstance("AES")
        kg.init(192, SecureRandom())
        return kg.generateKey()
    }
}
