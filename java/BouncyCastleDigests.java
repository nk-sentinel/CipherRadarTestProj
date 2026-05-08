package benchmark;

import org.bouncycastle.crypto.digests.*;

public class BouncyCastleDigests {

    // EXPECTED: SHA-256 | - | - | info | quantum-safe
    public void sha256() { new SHA256Digest(); }

    // EXPECTED: SHA-384 | - | - | info | quantum-safe
    public void sha384() { new SHA384Digest(); }

    // EXPECTED: SHA-512 | - | - | info | quantum-safe
    public void sha512() { new SHA512Digest(); }

    // EXPECTED: SHA-224 | - | - | info | quantum-safe
    public void sha224() { new SHA224Digest(); }

    // EXPECTED: SHA-1 | - | - | medium | quantum-vulnerable
    public void sha1() { new SHA1Digest(); } // DEPRECATED

    // EXPECTED: SHA3-256 | - | - | info | quantum-safe
    public void sha3_256() { new SHA3Digest(256); }

    // EXPECTED: SHA3-384 | - | - | info | quantum-safe
    public void sha3_384() { new SHA3Digest(384); }

    // EXPECTED: SHA3-512 | - | - | info | quantum-safe
    public void sha3_512() { new SHA3Digest(512); }

    // EXPECTED: MD5 | - | - | high | broken
    public void md5() { new MD5Digest(); } // BAD

    // EXPECTED: MD4 | - | - | critical | broken
    public void md4() { new MD4Digest(); } // BAD

    // EXPECTED: MD2 | - | - | critical | broken
    public void md2() { new MD2Digest(); } // BAD

    // EXPECTED: BLAKE2b | - | - | info | quantum-safe
    public void blake2b() { new Blake2bDigest(256); }

    // EXPECTED: BLAKE2s | - | - | info | quantum-safe
    public void blake2s() { new Blake2sDigest(256); }

    // EXPECTED: RIPEMD-160 | - | - | medium | quantum-safe
    public void ripemd160() { new RIPEMD160Digest(); }

    // EXPECTED: RIPEMD-128 | - | - | high | quantum-safe
    public void ripemd128() { new RIPEMD128Digest(); }

    // EXPECTED: RIPEMD-256 | - | - | info | quantum-safe
    public void ripemd256() { new RIPEMD256Digest(); }

    // EXPECTED: Whirlpool | - | - | info | quantum-safe
    public void whirlpool() { new WhirlpoolDigest(); }

    // EXPECTED: Tiger | - | - | medium | quantum-safe
    public void tiger() { new TigerDigest(); }

    // EXPECTED: SM3 | - | - | info | quantum-safe
    public void sm3() { new SM3Digest(); }

    // EXPECTED: GOST3411 | - | - | info | quantum-safe
    public void gost3411() { new GOST3411Digest(); }

    // EXPECTED: SHAKE-256 | - | - | info | quantum-safe
    public void shake256() { new SHAKEDigest(256); }

    // EXPECTED: Keccak-256 | - | - | info | quantum-safe
    public void keccak256() { new KeccakDigest(256); }

    // EXPECTED: Skein-256 | - | - | info | quantum-safe
    public void skein256() { new SkeinDigest(256, 256); }
}
