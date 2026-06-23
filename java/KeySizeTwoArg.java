package com.cipherradar.bench;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;

// Two-argument initialize(keysize, SecureRandom) — the standard JCA overload.
public class KeySizeTwoArg {
    // EXPECTED: RSA | - | 3072 | medium | quantum-vulnerable
    public static KeyPairGenerator make() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(3072, new SecureRandom());
        return kpg;
    }
}
