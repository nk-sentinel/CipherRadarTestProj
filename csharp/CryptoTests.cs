using System;
using System.IO;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;

namespace Benchmark
{
    public class CryptoTests
    {
        // EXPECTED: AES | - | 256 | info | quantum-safe
        public byte[] EncryptAES(byte[] key, byte[] plaintext)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();
            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }

        // EXPECTED: 3DES | - | 168 | high | quantum-safe
        public byte[] EncryptTripleDES(byte[] key, byte[] plaintext)
        {
            using var des3 = TripleDES.Create(); // DEPRECATED
            des3.Key = key;
            using var encryptor = des3.CreateEncryptor();
            return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }

        // EXPECTED: DES | - | 56 | critical | broken
        public byte[] EncryptDES(byte[] key, byte[] plaintext)
        {
            using var des = DES.Create(); // BAD: broken cipher
            des.Key = key;
            using var encryptor = des.CreateEncryptor();
            return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }

        // EXPECTED: RSA | - | 2048 | medium | quantum-vulnerable
        public RSA GenerateRSA2048()
        {
            return RSA.Create(2048);
        }

        // EXPECTED: RSA | - | 4096 | low | quantum-vulnerable
        public RSA GenerateRSA4096()
        {
            return RSA.Create(4096);
        }

        // EXPECTED: ECDSA | - | 256 | low | quantum-vulnerable
        public ECDsa GenerateECDSA()
        {
            return ECDsa.Create(ECCurve.NamedCurves.nistP256);
        }

        // EXPECTED: ECDSA | - | 384 | low | quantum-vulnerable
        public ECDsa GenerateECDSAP384()
        {
            return ECDsa.Create(ECCurve.NamedCurves.nistP384);
        }

        // EXPECTED: SHA-256 | - | - | info | quantum-safe
        public byte[] HashSHA256(byte[] data)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(data);
        }

        // EXPECTED: SHA-384 | - | - | info | quantum-safe
        public byte[] HashSHA384(byte[] data)
        {
            using var sha = SHA384.Create();
            return sha.ComputeHash(data);
        }

        // EXPECTED: SHA-512 | - | - | info | quantum-safe
        public byte[] HashSHA512(byte[] data)
        {
            using var sha = SHA512.Create();
            return sha.ComputeHash(data);
        }

        // EXPECTED: SHA-1 | - | - | medium | quantum-vulnerable
        public byte[] HashSHA1(byte[] data)
        {
            using var sha = SHA1.Create(); // DEPRECATED
            return sha.ComputeHash(data);
        }

        // EXPECTED: MD5 | - | - | high | broken
        public byte[] HashMD5(byte[] data)
        {
            using var md5 = MD5.Create(); // BAD
            return md5.ComputeHash(data);
        }

        // EXPECTED: HMAC-SHA256 | - | - | info | quantum-safe
        public byte[] ComputeHMAC(byte[] key, byte[] data)
        {
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(data);
        }

        // EXPECTED: HMAC-SHA512 | - | - | info | quantum-safe
        public byte[] ComputeHMACSHA512(byte[] key, byte[] data)
        {
            using var hmac = new HMACSHA512(key);
            return hmac.ComputeHash(data);
        }

        // EXPECTED: PBKDF2 | - | - | critical | quantum-safe
        public byte[] DeriveKeyWeak(string password, byte[] salt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100); // BAD: low iterations
            return pbkdf2.GetBytes(32);
        }

        // EXPECTED: PBKDF2 | - | - | info | quantum-safe
        public byte[] DeriveKeyStrong(string password, byte[] salt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 600000); // GOOD
            return pbkdf2.GetBytes(32);
        }

        // EXPECTED: TLS | 1.0 | - | critical | quantum-vulnerable
        public void WeakTLS(SslStream stream)
        {
            stream.AuthenticateAsClient("example.com", null, SslProtocols.Tls, false); // BAD
        }

        // EXPECTED: TLS | 1.3 | - | info | quantum-safe
        public void StrongTLS(SslStream stream)
        {
            stream.AuthenticateAsClient("example.com", null, SslProtocols.Tls13, true); // GOOD
        }
    }
}
