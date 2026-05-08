package benchmark;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Security;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Test cases for CBOM inventory OpenGrep rules.
 * These test cross-statement patterns that Pass 1 cannot detect alone.
 */
public class CbomInventoryTests {

    // ── Rule 3: KDF → Derived Key → Cipher Chain ──
    // EXPECTED: CBOM links PBKDF2 key derivation to AES cipher usage
    public void kdfToCipherChain() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray(), new byte[16], 310000, 256);
        SecretKey derivedKey = factory.generateSecret(spec);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, derivedKey);
    }

    // ── Rule 5: KeyGenerator → Cipher Usage Chain ──
    // EXPECTED: CBOM links key generation to cipher consumption
    public void keyGenToCipher() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey key = kg.generateKey();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
    }

    // ── Rule 6: Config-Driven Algorithm Selection ──
    // EXPECTED: CBOM tracks algorithm from environment variable
    public void configDrivenAlgorithm() throws Exception {
        String algo = System.getenv("CRYPTO_ALGORITHM");
        if (algo == null) algo = "AES/GCM/NoPadding";
        Cipher cipher = Cipher.getInstance(algo);
    }

    // ── Rule 6 variant: Algorithm from system properties ──
    public void propertyDrivenAlgorithm(java.util.Properties props) throws Exception {
        String algo = props.getProperty("cipher.algorithm");
        Cipher cipher = Cipher.getInstance(algo);
    }

    // ── Rule 8: Certificate Load → TLS Context ──
    // EXPECTED: CBOM links certificate to TLS configuration
    public void certToTlsContext() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("/path/to/keystore.p12"), "password".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(ks);

        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, tmf.getTrustManagers(), null);
    }

    // ── Rule 9: Crypto Provider Registration ──
    // EXPECTED: CBOM records provider change affecting crypto implementations
    public void registerProvider() {
        // Register BouncyCastle provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public void insertProvider() {
        Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    // ── Rule 4: TLS Version Enforcement ──
    // EXPECTED: CBOM records TLS version pinning
    public void tlsVersionEnforcement() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, null, null);
    }
}
