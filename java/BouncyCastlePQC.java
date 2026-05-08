package benchmark;

// Post-Quantum Cryptography test patterns
// CBOMkit v1.4.5 detects these; CipherRadar may not

import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyEncapsulation;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSSigner;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.LMSSigner;
import org.bouncycastle.pqc.crypto.lms.HSSSigner;
import org.bouncycastle.pqc.crypto.ntru.NTRUEngine;
import org.bouncycastle.pqc.crypto.bike.BIKEKEMGenerator;
import org.bouncycastle.pqc.crypto.cmce.CMCEKEMGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;

public class BouncyCastlePQC {

    // === NIST Standard PQC Algorithms ===

    // EXPECTED: ML-DSA | - | - | info | quantum-safe
    public void mldsaSigner() { new MLDSASigner(); }

    // EXPECTED: ML-DSA | - | - | info | quantum-safe
    public void mldsaKeyGen() { new MLDSAKeyPairGenerator(); }

    // EXPECTED: ML-KEM | - | - | info | quantum-safe
    public void mlkemKeyGen() { new MLKEMKeyPairGenerator(); }

    // EXPECTED: ML-KEM | - | - | info | quantum-safe
    public void mlkemEncaps() { new MLKEMKeyEncapsulation(); }

    // === NIST Round 3+ PQC ===

    // EXPECTED: SPHINCS+ | - | - | info | quantum-safe
    public void sphincsPlusSigner() { new SPHINCSPlusSigner(); }

    // EXPECTED: SPHINCS+ | - | - | info | quantum-safe
    public void sphincsPlusKeyGen() { new SPHINCSPlusKeyPairGenerator(); }

    // EXPECTED: Falcon | - | - | info | quantum-safe
    public void falconSigner() { new FalconSigner(); }

    // EXPECTED: Falcon | - | - | info | quantum-safe
    public void falconKeyGen() { new FalconKeyPairGenerator(); }

    // === Hash-Based Signatures ===

    // EXPECTED: XMSS | - | - | info | quantum-safe
    public void xmssSigner() { new XMSSSigner(); }

    // EXPECTED: XMSS-MT | - | - | info | quantum-safe
    public void xmssMTSigner() { new XMSSMTSigner(); }

    // EXPECTED: XMSS | - | - | info | quantum-safe
    public void xmssKeyGen() { new XMSSKeyPairGenerator(); }

    // EXPECTED: LMS | - | - | info | quantum-safe
    public void lmsSigner() { new LMSSigner(); }

    // EXPECTED: HSS | - | - | info | quantum-safe
    public void hssSigner() { new HSSSigner(); }

    // === KEM (Key Encapsulation Mechanisms) ===

    // EXPECTED: NTRU | - | - | info | quantum-safe
    public void ntruEngine() { new NTRUEngine(); }

    // EXPECTED: BIKE | - | - | info | quantum-safe
    public void bikeKEM() { new BIKEKEMGenerator(null); }

    // EXPECTED: Classic McEliece | - | - | info | quantum-safe
    public void cmceKEM() { new CMCEKEMGenerator(null); }

    // EXPECTED: HQC | - | - | info | quantum-safe
    public void hqcKEM() { new HQCKEMGenerator(null); }

    // === Deprecated PQC (replaced by ML-KEM/ML-DSA) ===

    // EXPECTED: Kyber | - | - | low | quantum-safe
    public void kyberKEM() { new KyberKEMGenerator(null); } // Deprecated: use ML-KEM

    // EXPECTED: Dilithium | - | - | low | quantum-safe
    public void dilithiumSigner() { new DilithiumSigner(); } // Deprecated: use ML-DSA
}
