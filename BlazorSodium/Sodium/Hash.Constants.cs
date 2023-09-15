namespace BlazorSodium.Sodium
{
    public static partial class Hash
    {
        public static uint BYTES
        {
            get => (uint)Sodium.GetConstantNumber_Interop("crypto_hash_BYTES");
        }

        public static uint HMAC_SHA512_KEYBYTES
        {
            get => (uint)Sodium.GetConstantNumber_Interop("crypto_auth_hmacsha512_KEYBYTES");
        }

        public static uint HMAC_SHA512_BYTES
        {
            get => (uint)Sodium.GetConstantNumber_Interop("crypto_auth_hmacsha512_BYTES");
        }
    }
}
