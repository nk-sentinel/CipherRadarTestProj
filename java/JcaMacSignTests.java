package benchmark;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class JcaMacSignTests {

    // EXPECTED: HMAC-SHA256 | - | - | info | quantum-safe
    public byte[] hmacSHA256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    // EXPECTED: HMAC-SHA384 | - | - | info | quantum-safe
    public byte[] hmacSHA384(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(new SecretKeySpec(key, "HmacSHA384"));
        return mac.doFinal(data);
    }

    // EXPECTED: HMAC-SHA512 | - | - | info | quantum-safe
    public byte[] hmacSHA512(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(key, "HmacSHA512"));
        return mac.doFinal(data);
    }

    // EXPECTED: HMAC-MD5 | - | - | high | broken
    public byte[] hmacMD5(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5"); // BAD
        mac.init(new SecretKeySpec(key, "HmacMD5"));
        return mac.doFinal(data);
    }

    // EXPECTED: SHA256withRSA | - | - | low | quantum-vulnerable
    public byte[] signSHA256withRSA(java.security.PrivateKey key, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    // EXPECTED: SHA384withRSA | - | - | low | quantum-vulnerable
    public byte[] signSHA384withRSA(java.security.PrivateKey key, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA384withRSA");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    // EXPECTED: SHA256withECDSA | - | - | low | quantum-vulnerable
    public byte[] signSHA256withECDSA(java.security.PrivateKey key, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    // EXPECTED: MD5withRSA | - | - | critical | broken
    public byte[] signMD5withRSA(java.security.PrivateKey key, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("MD5withRSA"); // BAD
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    // EXPECTED: SHA1withRSA | - | - | high | quantum-vulnerable
    public byte[] signSHA1withRSA(java.security.PrivateKey key, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA"); // DEPRECATED
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    // EXPECTED: RSASSA-PSS | - | - | info | quantum-vulnerable
    public byte[] signPSS(java.security.PrivateKey key, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("RSASSA-PSS"); // GOOD
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    // EXPECTED: DH | - | - | medium | quantum-vulnerable
    public void keyAgreementDH() throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
    }

    // EXPECTED: ECDH | - | - | low | quantum-vulnerable
    public void keyAgreementECDH() throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    }
}
