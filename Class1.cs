using System;
using System.IO;
using System.Security.Cryptography;
namespace PowerLib
{
    public static class Encryption
    {

        public static MemoryStream Encrypt(MemoryStream plaintext, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            var output = new MemoryStream();

            // prepend IV
            output.Write(aes.IV, 0, aes.IV.Length);

            using (var crypto = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                plaintext.Position = 0;
                plaintext.CopyTo(crypto);
            }

            output.Position = 0;
            return output;
        }

        public static MemoryStream Decrypt(MemoryStream encrypted, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            encrypted.Position = 0;

            // read IV
            byte[] iv = new byte[16];
            encrypted.Read(iv, 0, iv.Length);
            aes.IV = iv;

            var output = new MemoryStream();

            using (var crypto = new CryptoStream(encrypted, aes.CreateDecryptor(), CryptoStreamMode.Read))
            {
                crypto.CopyTo(output);
            }

            output.Position = 0;
            return output;
        }

        public static byte[] Encrypt(byte[] plaintext, byte[] key)
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            using (var aes = new AesGcm(key, 16))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            byte[] result = new byte[nonce.Length + tag.Length + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
            Buffer.BlockCopy(tag, 0, result, nonce.Length, tag.Length);
            Buffer.BlockCopy(ciphertext, 0, result, nonce.Length + tag.Length, ciphertext.Length);

            return result;
        }

        public static byte[] Decrypt(byte[] encrypted, byte[] key)
        {
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[encrypted.Length - nonce.Length - tag.Length];

            Buffer.BlockCopy(encrypted, 0, nonce, 0, nonce.Length);
            Buffer.BlockCopy(encrypted, nonce.Length, tag, 0, tag.Length);
            Buffer.BlockCopy(encrypted, nonce.Length + tag.Length, ciphertext, 0, ciphertext.Length);

            byte[] plaintext = new byte[ciphertext.Length];

            using (var aes = new AesGcm(key, 16))
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
            }

            return plaintext;
        }
    }
}
