using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace AesEncOnly
{
    public class AesEncryption
    {
        public byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            string textToEncrypt = "Test String";
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] cipherText;
            
            using (SymmetricAlgorithm aesAlg = SymmetricAlgorithm.Create("AES"))
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                var originalText = Encoding.UTF8.GetBytes(textToEncrypt);
                cipherText = encryptor.TransformFinalBlock(originalText, 0, originalText.Length);
            }

            // Return the encrypted bytes from the memory stream.
            return cipherText;
        }
    }
}
