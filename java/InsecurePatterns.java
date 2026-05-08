package benchmark;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Random;

public class InsecurePatterns {

    // EXPECTED: Random | - | - | high | quantum-safe
    // Weak PRNG used for security-sensitive value
    public byte[] weakPRNG() {
        Random rand = new Random(); // BAD: not cryptographically secure
        byte[] token = new byte[32];
        rand.nextBytes(token);
        return token;
    }

    // EXPECTED: SecureRandom | - | - | medium | quantum-safe
    // SecureRandom with hardcoded seed (reduces entropy)
    public SecureRandom seededSecureRandom() {
        SecureRandom sr = new SecureRandom(new byte[]{1, 2, 3, 4, 5}); // BAD: fixed seed
        return sr;
    }

    // EXPECTED: X509TrustManager | - | - | critical | quantum-vulnerable
    // Trust-all manager — disables certificate validation
    public void trustAllSetup() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {} // BAD
            }
        }, null);
    }

    // EXPECTED: HostnameVerifier | - | - | critical | quantum-vulnerable
    // Hostname verification bypass
    public void hostnameBypass() {
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true); // BAD
    }

    // EXPECTED: AES | ECB | - | high | quantum-safe
    // Static IV reuse
    private static final byte[] STATIC_IV = new byte[]{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    }; // BAD: static IV

    // EXPECTED: AES | CBC | - | high | quantum-safe
    public byte[] staticIVEncrypt(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(STATIC_IV)); // BAD
        return cipher.doFinal(data);
    }

    // EXPECTED: AES | ECB | - | high | quantum-safe
    // ECB mode for multi-block encryption
    public byte[] ecbMultiBlock(byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // BAD
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] largeData = new byte[1024]; // Multiple AES blocks
        return cipher.doFinal(largeData);
    }

    // EXPECTED: RSA | PKCS1 | - | medium | quantum-vulnerable
    // RSA without specifying padding (defaults to PKCS1)
    public byte[] rsaDefaultPadding(java.security.PublicKey pub, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA"); // BAD: defaults to PKCS1Padding
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        return cipher.doFinal(data);
    }
}
