using BlazorSodium.Sodium.Models;
using System.Runtime.Versioning;

namespace BlazorSodium.Sodium
{
   [SupportedOSPlatform("browser")]
   public static partial class Hash
   {
      /// <summary>
      /// Hash the provided message using a SHA-2 hashing function.
      /// </summary>
      /// <param name="message"></param>
      /// <returns></returns>
      /// <see cref="https://github.com/jedisct1/libsodium.js/blob/master/wrapper/symbols/crypto_hash.json"/>
      public static byte[] Crypto_Hash(byte[] message)
         => Crypto_Hash_Interop(message);

      /// <summary>
      /// Hash the provided message using a SHA-2 hashing function.
      /// </summary>
      /// <param name="message"></param>
      /// <returns></returns>
      /// <see cref="https://github.com/jedisct1/libsodium.js/blob/master/wrapper/symbols/crypto_hash.json"/>
      public static byte[] Crypto_Hash(string message)
         => Crypto_Hash_Interop(message);





    }
}
