package benchmark;

import org.bouncycastle.crypto.signers.*;

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
}
