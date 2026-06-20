package com.cipherradar.bench;

import java.security.KeyPairGenerator;

// Tests JCA key-size method-chaining capture (getInstance + initialize).
public class KeySizeChaining {
    // EXPECTED: RSA keypair generation with KeySize/classicalSecurityLevel = 2048
    public static void rsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }

    // EXPECTED: RSA-3072 via a constant-propagated key size
    public static void rsaConst() throws Exception {
        int bits = 3072;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(bits);
    }
}
