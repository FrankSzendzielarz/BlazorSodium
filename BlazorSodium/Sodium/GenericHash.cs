﻿using BlazorSodium.Sodium.Models;
using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;

namespace BlazorSodium.Sodium
{
   public static partial class GenericHash
   {
      /// <summary>
      /// Generate a fingerprint of the provided message.
      /// </summary>
      /// <param name="hashLength"></param>
      /// <param name="message"></param>
      /// <param name="key">Optional.</param>
      /// <returns></returns>
      /// <see cref="https://github.com/jedisct1/libsodium.js/blob/master/wrapper/symbols/crypto_generichash.json"/>
      [SupportedOSPlatform("browser")]
      public static byte[] Crypto_GenericHash(uint hashLength, byte[] message, byte[] key = null)
         => Crypto_GenericHash_Internal(hashLength, message, key);

      /// <summary>
      /// Generate a fingerprint of the provided message.
      /// </summary>
      /// <param name="hashLength"></param>
      /// <param name="message"></param>
      /// <param name="key">Optional.</param>
      /// <returns></returns>
      /// <see cref="https://github.com/jedisct1/libsodium.js/blob/master/wrapper/symbols/crypto_generichash.json"/>
      [SupportedOSPlatform("browser")]
      public static byte[] Crypto_GenericHash(uint hashLength, string message, byte[] key = null)
         => Crypto_GenericHash_Internal(hashLength, message, key);

      /// <summary>
      /// ​Complete a multi-part hashing operation and returns the final hash.
      /// </summary>
      /// <param name="stateAddress"></param>
      /// <param name="hashLength"></param>
      /// <returns></returns>
      /// <see cref="https://github.com/jedisct1/libsodium.js/blob/master/wrapper/symbols/crypto_generichash_final.json"/>
      [SupportedOSPlatform("browser")]
      public static byte[] Crypto_GenericHash_Final(StateAddress stateAddress, uint hashLength)
         => Crypto_GenericHash_Final_Internal(stateAddress.Value, hashLength);

      /// <summary>
      /// Initialize a new, multi-part hashing operation.
      /// </summary>
      /// <param name="hashLength"></param>
      /// <param name="key"></param>
      /// <returns></returns>
      /// <see cref="https://github.com/jedisct1/libsodium.js/blob/master/wrapper/symbols/crypto_generichash_init.json"/>
      [SupportedOSPlatform("browser")]
      public static StateAddress Crypto_GenericHash_Init(uint hashLength, byte[] key = null)
      {
         int stateAddress = Crypto_GenericHash_Init_Internal(key, hashLength);
         return new StateAddress(stateAddress);
      }

      /// <summary>
      /// Create a key of the recommended length.
      /// </summary>
      /// <returns></returns>
      /// <see cref="https://github.com/jedisct1/libsodium.js/blob/master/wrapper/symbols/crypto_generichash_keygen.json"/>
      [JSImport("sodium.crypto_generichash_keygen", "blazorSodium")]
      public static partial byte[] Crypto_GenericHash_KeyGen();

      /// <summary>
      /// Process the next part of a multi-part message.
      /// </summary>
      /// <param name="stateAddress"></param>
      /// <param name="messageChunk"></param>
      /// <see cref="https://github.com/jedisct1/libsodium.js/blob/master/wrapper/symbols/crypto_generichash_update.json"/>
      [SupportedOSPlatform("browser")]
      public static void Crypto_GenericHash_Update(StateAddress stateAddress, byte[] messageChunk)
         => Crypto_GenericHash_Update_Internal(stateAddress.Value, messageChunk);
   }
}
