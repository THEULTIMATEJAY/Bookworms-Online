using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Bookworms_Online.Services
{
    public class EncryptionService
    {
        private readonly string encryptionKey = "J8fV2X9pL6mQzB4rT1nYcW7dG0aK5sH3\r\n"; // Change this!

        public string Encrypt(string text)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(encryptionKey.Substring(0, 32));
            byte[] iv = new byte[16]; // Initialization vector

            using (Aes aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    using (StreamWriter writer = new StreamWriter(cs))
                    {
                        writer.Write(text);
                    }

                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        public string Decrypt(string cipherText)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(encryptionKey.Substring(0, 32));
            byte[] iv = new byte[16];

            using (Aes aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (StreamReader reader = new StreamReader(cs))
                {
                    return reader.ReadToEnd();
                }
            }
        }

    }
}
