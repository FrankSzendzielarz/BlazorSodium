using Algorand.Algod.Model.Transactions;
using Algorand.Algod;
using Algorand.Utils;
using Algorand;
using BlazorSodium.Services;
using BlazorSodium.Sodium;
using BlazorSodium.Sodium.Models;
using Microsoft.AspNetCore.Components;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using Algorand.Algod.Model;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace BlazorSodium.Demo.Shared
{
    
    [SupportedOSPlatform("browser")]
   public partial class BlazorSodiumComponent : ComponentBase
   {
        private const int BITS_PER_WORD = 11;
        private const int CHECKSUM_LEN_WORDS = 1;
        private const int KEY_LEN_BYTES = 32;
        private const int MNEM_LEN_WORDS = 25; // includes checksum word
        private const int PADDING_ZEROS = BITS_PER_WORD - ((KEY_LEN_BYTES * 8) % BITS_PER_WORD);
        private const char MNEMONIC_DELIM = ' ';
        [Inject]
      IBlazorSodiumService BlazorSodiumService { get; set; }
    
        protected override async Task OnInitializedAsync()
      {
         await BlazorSodiumService.InitializeAsync();
         Sodium.Sodium.PrintSodium();

         string password = "my test password";
         uint interactiveOpsLimit = PasswordHash.OPSLIMIT_INTERACTIVE;
         uint interactiveMemLimit = PasswordHash.MEMLIMIT_INTERACTIVE;
         string hashedPassword = PasswordHash.Crypto_PwHash_Str(password, interactiveOpsLimit, interactiveMemLimit);
         Console.WriteLine($"Hashed password: {hashedPassword}");

         bool needsRehash = PasswordHash.Crypto_PwHash_Str_Needs_Rehash(hashedPassword, interactiveOpsLimit, interactiveMemLimit);
         Console.WriteLine($"Password needs rehash: {needsRehash}");

         bool invalidVerification = PasswordHash.Crypto_PwHash_Str_Verify(hashedPassword, "bad password");
         Console.WriteLine($"Bad password is caught: {!invalidVerification}");

         bool validVerification = PasswordHash.Crypto_PwHash_Str_Verify(hashedPassword, password);
         Console.WriteLine($"Good password is accepted: {validVerification}");

         GenericHash.Crypto_GenericHash_Init(GenericHash.BYTES);

         byte[] dataToPad = "foo"u8.ToArray();
         Console.WriteLine(Convert.ToHexString(dataToPad));
         byte[] paddedData = Padding.Pad(dataToPad, 8);
         Console.WriteLine(Convert.ToHexString(paddedData));
         byte[] unpaddedData = Padding.Unpad(paddedData, 8);
         Console.WriteLine(Convert.ToHexString(unpaddedData));
      }

      private string SaltString { get; set; }
      protected byte[] Salt { get; set; }

      
       
        private  int[] ToUintNArray(byte[] arr)
        {
            int buffer = 0;
            int numBits = 0;
            int[] ret = new int[(arr.Length * 8 + BITS_PER_WORD - 1) / BITS_PER_WORD];

            int j = 0;

            for (int i = 0; i < arr.Length; i++)
            {
                // numBits is how many bits in arr[i] we've processed
                int v = arr[i];
                if (v < 0) v += 256; // deal with java signed types
                buffer |= (v << numBits);
                numBits += 8;
                if (numBits >= BITS_PER_WORD)
                {
                    // add to output
                    ret[j] = buffer & 0x7ff;
                    j++;
                    // drop from buffer
                    buffer = buffer >> BITS_PER_WORD;
                    numBits -= BITS_PER_WORD;
                }
            }
            if (numBits != 0)
            {
                ret[j] = buffer & 0x7ff;
            }
            return ret;
        }

        
        [SupportedOSPlatform("browser")]
        protected async Task GenerateRandomSalt()
      {
            byte[] data = Encoding.UTF8.GetBytes("test");
            Sha512256.Compute(data, out byte[] hash);
       //     byte[] hash = Hash.Crypto_Hash_Sha256(data);
            
      

            var ALGOD_API_ADDR = "http://localhost:4001/";
            var ALGOD_API_TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

            // This boilerplate creates an Account object with a private key represented by a mnemnonic.
            //
            //   If using Sandbox, please use the following commands to replace the below mnemonic:
            //   ./sandbox goal account list
            //   ./sandbox goal account export -a <address>
            var src = new Account("arrive transfer silent pole congress loyal snap dirt dwarf relief easily plastic federal found siren point know polar quit very vanish ensure humor abstract broken");

            var DEST_ADDR = "5KFWCRTIJUMDBXELQGMRBGD2OQ2L3ZQ2MB54KT2XOQ3UWPKUU4Y7TQ4X7U";


            var httpClient = HttpClientConfigurator.ConfigureHttpClient(ALGOD_API_ADDR, ALGOD_API_TOKEN);
            DefaultApi algodApiInstance = new DefaultApi(httpClient);

            var supply = await algodApiInstance.GetSupplyAsync();


            var accountInfo = await algodApiInstance.AccountInformationAsync(src.Address.ToString(), null, null);



            var transParams = await algodApiInstance.TransactionParamsAsync();

            var amount = Utils.AlgosToMicroalgos(1);
            var tx = PaymentTransaction.GetPaymentTransactionFromNetworkTransactionParameters(src.Address, new Address(DEST_ADDR), amount, "pay message", transParams);
            var signedTx = tx.Sign(src);



            // send the transaction to the network
            var id = await Utils.SubmitTransaction(algodApiInstance, signedTx);


            var resp = await Utils.WaitTransactionToComplete(algodApiInstance, id.Txid);






            Salt = new byte[16];
         RandomBytes.RandomBytes_Buf(16).CopyTo(Salt, 0);
         SaltString = Convert.ToHexString(Salt);
      }

      protected string PublicKey { get; set; }
      protected string PrivateKey { get; set; }

      [SupportedOSPlatform("browser")]
      protected void GeneratePublicKeySignatureKeyPair()
      {
         Ed25519KeyPair keyPair = PublicKeySignature.Crypto_Sign_KeyPair();
         PublicKey = Convert.ToHexString(keyPair.PublicKey);
         PrivateKey = Convert.ToHexString(keyPair.PrivateKey);
      }

      [SupportedOSPlatform("browser")]
      protected async Task GenerateRandomNumber()
      {


          


            uint randomNumber = RandomBytes.RandomBytes_Random();
         Console.WriteLine(randomNumber);
      }

      protected string SecretStreamKey { get; set; }
      protected byte[] SecretStreamKeyBytes { get; set; }
      [SupportedOSPlatform("browser")]
      protected void GenerateSecretStreamKey()
      {
         uint keySize = SecretStream.KEY_BYTES;
         SecretStreamKeyBytes = new byte[keySize];
         SecretStream.Crypto_SecretStream_XChaCha20Poly1305_KeyGen().CopyTo(SecretStreamKeyBytes, 0);
         SecretStreamKey = Convert.ToHexString(SecretStreamKeyBytes);
      }

      protected string SecretStreamPlaintext { get; set; }
      protected string HexCiphertext { get; set; }
      protected string DecryptedText { get; set; }
      [SupportedOSPlatform("browser")]
      protected void EncryptSecretStream()
      {
         // Encrypt
         SecretStreamPushData initData = SecretStream.Crypto_SecretStream_XChaCha20Poly1305_Init_Push(SecretStreamKeyBytes);
         string[] stringParts = SecretStreamPlaintext.Split(' ');
         List<byte[]> cipherParts = new List<byte[]>(stringParts.Length);

         for (int i = 0; i < stringParts.Length; i++)
         {
            uint tag = i + 1 < stringParts.Length
               ? SecretStream.TAG_MESSAGE
               : SecretStream.TAG_FINAL;

            byte[] cipherPart = SecretStream.Crypto_SecretStream_XChaCha20Poly1305_Push(initData.StateAddress, stringParts[i], tag);
            cipherParts.Add(cipherPart);
         }
         HexCiphertext = Convert.ToHexString(cipherParts.SelectMany(x => x).ToArray());
         Console.WriteLine(HexCiphertext);

         // Decrypt
         StateAddress stateAddress = SecretStream.Crypto_SecretStream_XChaCha20Poly1305_Init_Pull(initData.Header, SecretStreamKeyBytes);
         List<byte[]> plaintextParts = new List<byte[]>(cipherParts.Count);
         for (int i = 0; i < cipherParts.Count; i++)
         {
            SecretStreamPullData pullData = SecretStream.Crypto_SecretStream_XChaCha20Poly1305_Pull(stateAddress, cipherParts[i], null);
            plaintextParts.Add(pullData.Message);
         }
         DecryptedText = Encoding.UTF8.GetString(plaintextParts.SelectMany(x => x).ToArray());
      }
   }
}
