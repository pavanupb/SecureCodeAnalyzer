using System;
using System.Security.Cryptography;

namespace AesEncOnly
{
    class Program
    {
        public static void Main()
        {
            string original = "This is secret message";            
            byte[] key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            byte[] iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

            // Create a new instance of the Aes
            // class.  This generates a new key and initialization
            // vector (IV).
            using (SymmetricAlgorithm myAes = SymmetricAlgorithm.Create("AES"))
            {
                myAes.Key = key;
                myAes.IV = iv;

                AesEncryption encryptDecrypt = new AesEncryption();

                byte[] ciphetText = encryptDecrypt.EncryptStringToBytes_Aes(original, myAes.Key, myAes.IV);

                //Display the original data and the decrypted data.
                Console.WriteLine("Original:   {0}", original);
            }
        }
    }
}
