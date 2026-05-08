package benchmark;

import java.security.MessageDigest;

public class JcaHashTests {

    // EXPECTED: MD5 | - | - | high | broken
    public byte[] hashMD5(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data); // BAD
    }

    // EXPECTED: SHA-1 | - | - | medium | quantum-vulnerable
    public byte[] hashSHA1(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data); // DEPRECATED
    }

    // EXPECTED: SHA-224 | - | - | info | quantum-safe
    public byte[] hashSHA224(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-224").digest(data);
    }

    // EXPECTED: SHA-256 | - | - | info | quantum-safe
    public byte[] hashSHA256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data); // GOOD
    }

    // EXPECTED: SHA-384 | - | - | info | quantum-safe
    public byte[] hashSHA384(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-384").digest(data);
    }

    // EXPECTED: SHA-512 | - | - | info | quantum-safe
    public byte[] hashSHA512(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-512").digest(data);
    }

    // EXPECTED: SHA3-256 | - | - | info | quantum-safe
    public byte[] hashSHA3_256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA3-256").digest(data);
    }

    // EXPECTED: SHA3-384 | - | - | info | quantum-safe
    public byte[] hashSHA3_384(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA3-384").digest(data);
    }

    // EXPECTED: SHA3-512 | - | - | info | quantum-safe
    public byte[] hashSHA3_512(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA3-512").digest(data);
    }

    // EXPECTED: SHA-256 | - | - | info | quantum-safe
    // Constant propagation test
    public byte[] constPropHash(byte[] data) throws Exception {
        String algo = "SHA-256";
        MessageDigest md = MessageDigest.getInstance(algo);
        md.update(data);
        return md.digest();
    }
}
