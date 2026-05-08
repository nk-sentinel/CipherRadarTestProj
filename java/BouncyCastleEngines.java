package benchmark;

import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.paddings.*;

public class BouncyCastleEngines {

    // === Block Cipher Engines ===

    // EXPECTED: AES | - | - | info | quantum-safe
    public void aesEngine() { new AESEngine(); }

    // EXPECTED: AES | - | - | info | quantum-safe
    public void aesLightEngine() { new AESLightEngine(); }

    // EXPECTED: DES | - | 56 | critical | broken
    public void desEngine() { new DESEngine(); }

    // EXPECTED: 3DES | - | 168 | high | quantum-safe
    public void desedeEngine() { new DESedeEngine(); }

    // EXPECTED: Twofish | - | - | info | quantum-safe
    public void twofishEngine() { new TwofishEngine(); }

    // EXPECTED: Serpent | - | - | info | quantum-safe
    public void serpentEngine() { new SerpentEngine(); }

    // EXPECTED: Camellia | - | - | info | quantum-safe
    public void camelliaEngine() { new CamelliaEngine(); }

    // EXPECTED: Camellia | - | - | info | quantum-safe
    public void camelliaLightEngine() { new CamelliaLightEngine(); }

    // EXPECTED: Blowfish | - | - | medium | quantum-safe
    public void blowfishEngine() { new BlowfishEngine(); }

    // EXPECTED: RC2 | - | - | high | quantum-safe
    public void rc2Engine() { new RC2Engine(); }

    // EXPECTED: RC6 | - | - | info | quantum-safe
    public void rc6Engine() { new RC6Engine(); }

    // EXPECTED: SM4 | - | - | info | quantum-safe
    public void sm4Engine() { new SM4Engine(); }

    // EXPECTED: SEED | - | - | info | quantum-safe
    public void seedEngine() { new SEEDEngine(); }

    // EXPECTED: ARIA | - | - | info | quantum-safe
    public void ariaEngine() { new ARIAEngine(); }

    // EXPECTED: IDEA | - | - | medium | quantum-safe
    public void ideaEngine() { new IDEAEngine(); }

    // EXPECTED: CAST5 | - | - | medium | quantum-safe
    public void cast5Engine() { new CAST5Engine(); }

    // EXPECTED: CAST6 | - | - | info | quantum-safe
    public void cast6Engine() { new CAST6Engine(); }

    // EXPECTED: RC4 | - | - | critical | broken
    public void rc4Engine() { new RC4Engine(); }

    // === Block Cipher Modes ===

    // EXPECTED: AES | CBC | - | low | quantum-safe
    public void aesCBC() { new CBCBlockCipher(new AESEngine()); }

    // EXPECTED: AES | GCM | - | info | quantum-safe
    public void aesGCM() { new GCMBlockCipher(new AESEngine()); }

    // EXPECTED: AES | CCM | - | info | quantum-safe
    public void aesCCM() { new CCMBlockCipher(new AESEngine()); }

    // EXPECTED: AES | CTR | - | info | quantum-safe
    public void aesCTR() { new SICBlockCipher(new AESEngine()); }

    // EXPECTED: AES | OFB | - | low | quantum-safe
    public void aesOFB() { new OFBBlockCipher(new AESEngine(), 128); }

    // EXPECTED: AES | CFB | - | low | quantum-safe
    public void aesCFB() { new CFBBlockCipher(new AESEngine(), 128); }

    // EXPECTED: AES | EAX | - | info | quantum-safe
    public void aesEAX() { new EAXBlockCipher(new AESEngine()); }

    // === Padding ===

    // EXPECTED: PKCS7 | - | - | info | quantum-safe
    public void pkcs7Padding() { new PKCS7Padding(); }

    // EXPECTED: ZeroByte | - | - | low | quantum-safe
    public void zeroPadding() { new ZeroBytePadding(); }
}
