using System.IO;
using System.Security.Cryptography;

namespace CodeSharpenerCryptoAnalysis.Test
{
    public class AESEncryption
    {
        public static void AesEncryptionAlgorithm()
        {
            string dataToEncrypt = "Test Data to Encrypt";
            byte[] encryptedValue;

            using (Aes aesEncryption = Aes.Create("DES"))
            {
                Aes aesEncryption1 = Aes.Create();
                aesEncryption.KeySize = 256;
                aesEncryption.Mode = CipherMode.ECB;                

                ICryptoTransform encryptor = aesEncryption.CreateEncryptor(aesEncryption.Key, aesEncryption.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swWriter = new StreamWriter(cryptoStream))
                        {
                            swWriter.Write(dataToEncrypt);
                        }
                        encryptedValue = msEncrypt.ToArray();
                    }
                }
            }
        }
    }
}
