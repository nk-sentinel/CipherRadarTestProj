package benchmark;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class JcaKeyGenTests {

    // EXPECTED: RSA | - | 1024 | critical | quantum-vulnerable
    public void generateRSA1024() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024); // BAD: weak key
    }

    // EXPECTED: RSA | - | 2048 | medium | quantum-vulnerable
    public void generateRSA2048() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }

    // EXPECTED: RSA | - | 4096 | low | quantum-vulnerable
    public void generateRSA4096() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
    }

    // EXPECTED: ECDSA | - | 256 | low | quantum-vulnerable
    public void generateECP256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
    }

    // EXPECTED: ECDSA | - | 384 | low | quantum-vulnerable
    public void generateECP384() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp384r1"));
    }

    // EXPECTED: ECDSA | - | 521 | low | quantum-vulnerable
    public void generateECP521() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp521r1"));
    }

    // EXPECTED: DSA | - | 2048 | medium | quantum-vulnerable
    public void generateDSA() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(2048);
    }

    // EXPECTED: AES | - | 128 | info | quantum-safe
    public void generateAES128() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
    }

    // EXPECTED: AES | - | 256 | info | quantum-safe
    public void generateAES256() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
    }

    // EXPECTED: HMAC-SHA256 | - | - | info | quantum-safe
    public void generateHmacKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
        kg.init(256);
    }

    // EXPECTED: DES | - | 56 | critical | broken
    public void generateDESKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("DES"); // BAD
    }

    // EXPECTED: AES | - | 128 | critical | quantum-safe
    // Hardcoded key material
    public void hardcodedKey() {
        byte[] keyBytes = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES"); // BAD: hardcoded key
    }

    // EXPECTED: AES | - | - | critical | quantum-safe
    // Hardcoded string key
    public void hardcodedStringKey() {
        String secret = "mySecretKey12345";
        SecretKeySpec key = new SecretKeySpec(secret.getBytes(), "AES"); // BAD
    }

    // EXPECTED: AES | - | - | critical | quantum-safe
    // Base64-encoded hardcoded key
    public void base64HardcodedKey() {
        String b64Key = "dGhpcyBpcyBhIHNlY3JldCBrZXkh";
        byte[] keyBytes = Base64.getDecoder().decode(b64Key);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES"); // BAD
    }

    // EXPECTED: PBKDF2 | - | - | critical | quantum-safe
    public void pbkdf2LowIterations() throws Exception {
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray(), new byte[16], 100, 256); // BAD: 100 iterations
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec);
    }

    // EXPECTED: PBKDF2 | - | - | info | quantum-safe
    public void pbkdf2HighIterations() throws Exception {
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray(), new byte[16], 600000, 256); // GOOD
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec);
    }
}
