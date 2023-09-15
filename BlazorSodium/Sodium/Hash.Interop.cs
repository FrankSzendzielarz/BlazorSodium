using BlazorSodium.Sodium.Models;
using System.Runtime.InteropServices.JavaScript;

namespace BlazorSodium.Sodium
{
    public static partial class Hash
    {
        /// <summary>
        /// Internal method.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        /// <see cref="https://github.com/jedisct1/libsodium.js/blob/master/wrapper/symbols/crypto_hash.json"/>
        [JSImport("sodium.crypto_hash", "blazorSodium")]
        internal static partial byte[] Crypto_Hash_Interop(byte[] message);

        /// <summary>
        /// Internal method.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        /// <see cref="https://github.com/jedisct1/libsodium.js/blob/master/wrapper/symbols/crypto_hash.json"/>
        [JSImport("sodium.crypto_hash", "blazorSodium")]
        internal static partial byte[] Crypto_Hash_Interop(string message);


        [JSImport("sodium.crypto_hash_sha256", "blazorSodium")]
        internal static partial byte[] Crypto_Hash_Sha256_Interop(byte[] message);

        [JSImport("sodium.crypto_hash_sha512_init", "blazorSodium")]
        internal static partial int Crypto_Hash_Sha512_Init_Interop(int stateAddress);

        [JSImport("sodium.crypto_auth_sha512_update", "blazorSodium")]
        internal static partial byte[] Crypto_Hash_Sha512_Update_Interop(int stateAddress, byte[] messageChunk);

        [JSImport("sodium.crypto_auth_sha512_final", "blazorSodium")]
        internal static partial byte[] Crypto_Hash_Sha512_Final_Interop(int stateAddress);




    }
}
