using System.Security.Cryptography;

// Aes.Create() + KeySize property assignment — the symmetric analog of the
// RSA KeySize property capture in KeySizeProperty.cs.
namespace CipherRadar.Bench
{
    public class AesKeySize
    {
        // EXPECTED: AES | - | 256 | info | quantum-safe
        public static Aes Make()
        {
            var aes = Aes.Create();
            aes.KeySize = 256;
            return aes;
        }
    }
}
