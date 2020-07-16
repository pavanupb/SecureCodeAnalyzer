using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AESEncryption
{
    class Program
    {
        //byte[] key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
        //byte[] iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
        public static void Main()
        {
            string original = "Here is some data to encrypt!";
            const string aesKey = "6Z8FgpPBeXg=";

            //Type1: ByteArray Declaration
            byte[] key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            byte[] iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

            //Type2: ByteArray Declaration
            byte[] testByte = new byte[] { 0x01, 0x02 };

            //Type3: ByteArray Declaration
            byte[] forLoopTestByte = new byte[7000];
            for(int i = 0; i < 16; i++)
            {
                forLoopTestByte[i] = 0x01;
            }

            StringBuilder b = new StringBuilder("Test");
            string taint1 = b.ToString();

            /*string t = new string("Test");
            string taint2 = t;*/

            byte[] aesByteKey = Convert.FromBase64String(aesKey);


            var testTaint = testByte;

            string test = ConfigurationManager.AppSettings["TextToEncrypt"].ToString();

            AESModel aesModel = new AESModel();
            aesModel.AESKey = key;
            aesModel.AESIV = iv;

            AESModel aesModel1 = new AESModel();            

            // Create a new instance of the Aes
            // class.  This generates a new key and initialization
            // vector (IV).
            using (SymmetricAlgorithm myAes = SymmetricAlgorithm.Create("AES"))
            {

                aesModel1.AESKey = myAes.Key;
                aesModel1.AESIV = myAes.IV;

                /*//Sanitizing the aesModel key and iv properties
                aesModel.AESKey = myAes.Key;
                aesModel.AESIV = myAes.IV;*/

                myAes.Key = aesModel.AESKey;
                myAes.IV = aesModel.AESIV;
                myAes.KeySize = 128;

                //EncDecTest encryptDecrypt = new EncDecTest();
                EncryptionDecryption encryptDecrypt = new EncryptionDecryption();

                //Sanitizing the original text string
                //original = test;

                //Sanitizing at wrong place
               /* aesModel.AESKey = myAes.Key;
                aesModel.AESIV = myAes.IV;*/

                byte[] ciphetText = encryptDecrypt.EncryptStringToBytes_Aes(original, myAes.Key, myAes.IV);
                string roundtrip = encryptDecrypt.DecryptStringFromBytes_Aes(ciphetText, myAes.Key, myAes.IV);

                /*// Encrypt the string to an array of bytes.
                byte[] ciphetText = EncryptStringToBytes_Aes(original, myAes.Key, myAes.IV);

                // Decrypt the bytes to a string.
                string roundtrip = DecryptStringFromBytes_Aes(ciphetText, myAes.Key, myAes.IV);*/

                /*EncryptionDecryption encryptionDecryption = new EncryptionDecryption();
                byte[] ciphetText = encryptionDecryption.EncryptStringToBytes_Aes(original, myAes.Key, myAes.IV);
                string roundtrip = encryptionDecryption.DecryptStringFromBytes_Aes(ciphetText, myAes.Key, myAes.IV);*/


                //Display the original data and the decrypted data.
                Console.WriteLine("Original:   {0}", original);
                Console.WriteLine("Round Trip: {0}", roundtrip);
            }
        }

        public static void KeyedHashAlgorithm(string[] args)
        {
            string plainText = "This is a sample text to be hashed";
            string sanitizedText = ConfigurationManager.AppSettings["TextToHash"];

            using (Rfc2898DeriveBytes hashedPassword = new Rfc2898DeriveBytes(plainText, 32, 50000, HashAlgorithmName.SHA1))
            {
                byte[] hashedValue = hashedPassword.GetBytes(32);
                string hashedString = Convert.ToBase64String(hashedValue);
            }
        }

        public static void EncryptDecryptText()
        {
            string original = "Here is some data to encrypt!";
            
            byte[] key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            byte[] iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

            using (SymmetricAlgorithm myAes = SymmetricAlgorithm.Create("AES"))
            {

                myAes.Key = key;
                myAes.IV = iv;
                myAes.KeySize = 256;

                //EncDecTest encryptDecrypt = new EncDecTest();
                EncryptionDecryption encryptDecrypt = new EncryptionDecryption();

                //Sanitizing the original text string
                //original = test;

                //Sanitizing at wrong place
                /* aesModel.AESKey = myAes.Key;
                 aesModel.AESIV = myAes.IV;*/

                byte[] ciphetText = encryptDecrypt.EncryptStringToBytes_Aes(original, myAes.Key, myAes.IV);
                string roundtrip = encryptDecrypt.DecryptStringFromBytes_Aes(ciphetText, myAes.Key, myAes.IV);              


                //Display the original data and the decrypted data.
                Console.WriteLine("Original:   {0}", original);
                Console.WriteLine("Round Trip: {0}", roundtrip);
            }

        }

        /*static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] cipherText;

            // Create an Aes object
            // with the specified key and IV.
            using (SymmetricAlgorithm aesAlg = SymmetricAlgorithm.Create("AES"))
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.BlockSize = 128;
                aesAlg.Padding = PaddingMode.ISO10126;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                var originalText = Encoding.UTF8.GetBytes(plainText);
                cipherText = encryptor.TransformFinalBlock(originalText, 0, originalText.Length);

            }

            // Return the encrypted bytes from the memory stream.
            return cipherText;
        }*/

        /*static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (SymmetricAlgorithm aesAlg = SymmetricAlgorithm.Create("AES"))
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.BlockSize = 128;
                aesAlg.Padding = PaddingMode.PKCS7;               

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                var decryptedBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                plaintext = Encoding.UTF8.GetString(decryptedBytes);


                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }*/
    }
}
