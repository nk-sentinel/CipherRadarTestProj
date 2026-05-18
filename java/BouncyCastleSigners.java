package benchmark;

import org.bouncycastle.crypto.signers.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import java.math.BigInteger;
import java.security.SecureRandom;

public class BouncyCastleSigners {

    // EXPECTED: Ed25519 | - | 256 | low | quantum-vulnerable
    public void ed25519() { new Ed25519Signer(); }

    // EXPECTED: Ed448 | - | 448 | low | quantum-vulnerable
    public void ed448() { new Ed448Signer(new byte[0]); }

    // EXPECTED: ECDSA | - | - | low | quantum-vulnerable
    public void ecdsa() { new ECDSASigner(); }

    // EXPECTED: DSA | - | - | medium | quantum-vulnerable
    public void dsa() { new DSASigner(); }

    // EXPECTED: RSA | - | - | low | quantum-vulnerable
    public void rsaDigest() { new RSADigestSigner(new org.bouncycastle.crypto.digests.SHA256Digest()); }

    // EXPECTED: RSA-PSS | - | - | info | quantum-vulnerable
    public void pssSigner() { new PSSSigner(new org.bouncycastle.crypto.engines.RSAEngine(), new org.bouncycastle.crypto.digests.SHA256Digest(), 32); }

    // EXPECTED: RSA | - | - | low | quantum-vulnerable
    public void genericSigner() { new GenericSigner(new org.bouncycastle.crypto.engines.RSAEngine(), new org.bouncycastle.crypto.digests.SHA256Digest()); }

    // EXPECTED: ISO9796-2 | - | - | medium | quantum-vulnerable
    public void iso9796d2() { new ISO9796d2Signer(new org.bouncycastle.crypto.engines.RSAEngine(), new org.bouncycastle.crypto.digests.SHA256Digest()); }

    // EXPECTED: Ed25519ph | - | 256 | low | quantum-vulnerable
    public void ed25519ph() { new Ed25519phSigner(new byte[0]); }

    // EXPECTED: Ed25519ctx | - | 256 | low | quantum-vulnerable
    public void ed25519ctx() { new Ed25519ctxSigner(new byte[0]); }

    // EXPECTED: ElGamal | - | 2048 | medium | quantum-vulnerable
    // ElGamal — discrete-log-based asymmetric encryption
    public void elgamal() {
        BigInteger p = BigInteger.ONE;
        BigInteger g = BigInteger.ONE;
        ElGamalParameters params = new ElGamalParameters(p, g);
        ElGamalKeyGenerationParameters kgp = new ElGamalKeyGenerationParameters(new SecureRandom(), params);
        ElGamalKeyPairGenerator kpg = new ElGamalKeyPairGenerator();
        kpg.init(kgp);
        AsymmetricCipherKeyPair pair = kpg.generateKeyPair();
        ElGamalEngine engine = new ElGamalEngine();
    }
}
