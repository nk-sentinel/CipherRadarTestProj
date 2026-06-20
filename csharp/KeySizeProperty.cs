using System.Security.Cryptography;

// Tests C# KeySize property-assignment capture (the C# analog of JCA chaining).
namespace CipherRadar.Bench
{
    public class KeySizeProperty
    {
        // EXPECTED: RSA with KeySize/classicalSecurityLevel = 2048 from property assignment
        public static RSA Make()
        {
            var rsa = RSA.Create();
            rsa.KeySize = 2048;
            return rsa;
        }
    }
}
