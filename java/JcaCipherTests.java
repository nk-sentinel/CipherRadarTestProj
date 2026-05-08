package benchmark;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class JcaCipherTests {

    // EXPECTED: AES | ECB | - | high | quantum-safe
    public byte[] aesECB(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // BAD: ECB mode
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(data);
    }

    // EXPECTED: AES | CBC | - | low | quantum-safe
    public byte[] aesCBC(byte[] key, byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    // EXPECTED: AES | GCM | - | info | quantum-safe
    public byte[] aesGCM(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // GOOD: AEAD
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return cipher.doFinal(data);
    }

    // EXPECTED: AES | CTR | - | info | quantum-safe
    public byte[] aesCTR(byte[] key, byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    // EXPECTED: AES | CFB | - | low | quantum-safe
    public byte[] aesCFB(byte[] key, byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    // EXPECTED: AES | OFB | - | low | quantum-safe
    public byte[] aesOFB(byte[] key, byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    // EXPECTED: DES | ECB | 56 | critical | broken
    public byte[] desECB(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding"); // BAD: broken cipher
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
        return cipher.doFinal(data);
    }

    // EXPECTED: 3DES | CBC | 168 | high | quantum-safe
    public byte[] tripleDesCBC(byte[] key, byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding"); // DEPRECATED
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    // EXPECTED: RC4 | - | - | critical | broken
    public byte[] rc4(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RC4"); // BAD: broken stream cipher
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "RC4"));
        return cipher.doFinal(data);
    }

    // EXPECTED: Blowfish | CBC | - | medium | quantum-safe
    public byte[] blowfishCBC(byte[] key, byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding"); // WEAK
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "Blowfish"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    // EXPECTED: RSA | PKCS1 | - | medium | quantum-vulnerable
    public byte[] rsaPKCS1(java.security.PublicKey pub, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // BAD: padding oracle
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        return cipher.doFinal(data);
    }

    // EXPECTED: RSA | OAEP | - | low | quantum-vulnerable
    public byte[] rsaOAEP(java.security.PublicKey pub, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); // GOOD
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        return cipher.doFinal(data);
    }

    // EXPECTED: AES | ECB | - | high | quantum-safe
    // Constant propagation test
    public byte[] constPropTest(byte[] key, byte[] data) throws Exception {
        String algo = "AES/ECB/PKCS5Padding";
        Cipher cipher = Cipher.getInstance(algo); // BAD: ECB via variable
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(data);
    }

    // EXPECTED: AES | ECB | - | high | quantum-safe
    // Missing mode defaults to ECB in many providers
    public byte[] aesNoMode(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES"); // BAD: defaults to ECB
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(data);
    }
}
