package benchmark;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.macs.*;
import org.bouncycastle.crypto.params.KeyParameter;

public class BouncyCastleMacKdf {

    // === MAC Algorithms ===

    // EXPECTED: HMAC-SHA256 | - | - | info | quantum-safe
    public void hmac() { new HMac(new SHA256Digest()); }

    // EXPECTED: AES-CMAC | - | - | info | quantum-safe
    public void cmac() { new CMac(new AESEngine()); }

    // EXPECTED: AES-GMAC | - | - | info | quantum-safe
    public void gmac() { new GMac(new org.bouncycastle.crypto.modes.GCMBlockCipher(new AESEngine())); }

    // EXPECTED: Poly1305 | - | - | info | quantum-safe
    public void poly1305() { new Poly1305(); }

    // EXPECTED: SipHash | - | - | info | quantum-safe
    public void siphash() { new SipHash(); }

    // EXPECTED: SipHash-128 | - | - | info | quantum-safe
    public void siphash128() { new SipHash128(); }

    // EXPECTED: KMAC | - | 256 | info | quantum-safe
    // KMAC256 — Keccak-based MAC (NIST SP 800-185)
    public void kmac256() {
        KMAC kmac = new KMAC(256, "test-context".getBytes());
        kmac.init(new KeyParameter(new byte[32]));
        kmac.update("data".getBytes(), 0, 4);
        byte[] out = new byte[32];
        kmac.doFinal(out, 0);
    }

    // === Key Derivation Functions ===

    // EXPECTED: HKDF | - | - | info | quantum-safe
    public void hkdf() { new HKDFBytesGenerator(new SHA256Digest()); }

    // EXPECTED: PBKDF2 | - | - | info | quantum-safe
    public void pbkdf2() {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
    }

    // EXPECTED: scrypt | - | - | info | quantum-safe
    public void scrypt() {
        byte[] derived = SCrypt.generate(new byte[16], new byte[16], 32768, 8, 1, 32);
    }

    // === Key Wrapping ===

    // EXPECTED: AES-KW | - | - | info | quantum-safe
    public void aesKeyWrap() {
        AESWrapEngine wrap = new AESWrapEngine();
    }

    // EXPECTED: AES-KW | - | - | info | quantum-safe
    public void aesKeyUnwrap() {
        AESWrapEngine unwrap = new AESWrapEngine();
    }
}
