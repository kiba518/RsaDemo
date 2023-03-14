using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RsaDemo
{
    public class AESUtil
    {

        /// <summary>
        /// 获取密钥 必须是32字节
        /// </summary>
        private string Key
        {
            get; set;
        }
        public AESUtil(string key)
        {
            Key = key;
        }
        /// <summary>
        /// 获取Aes32位密钥,【和java交互时不使用补0】
        /// </summary>
        /// <param name="key">Aes密钥字符串</param>
        /// <returns>Aes32位密钥</returns>
        public byte[] GetAesKey(string key)
        {
            if (string.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException("key", "Aes密钥不能为空");
            }
            if (key.Length < 32)
            {
                // 不足32补全
                key = key.PadRight(32, '0');
            }
            if (key.Length > 32)
            {
                key = key.Substring(0, 32);
            }
            return Encoding.UTF8.GetBytes(key);
        }
        /// <summary>
        /// AES加密
        /// </summary>
        /// <param name="plainStr">明文字符串</param>
        /// <returns>密文</returns>
        public string AESEncrypt(string encryptStr)
        {
            byte[] keyArray = Encoding.UTF8.GetBytes(Key); ;
            byte[] toEncryptArray = Encoding.UTF8.GetBytes(encryptStr);
            RijndaelManaged aes = new RijndaelManaged(); 
            aes.IV = Encoding.UTF8.GetBytes(Key); ;
            aes.Key = keyArray;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            ICryptoTransform cTransform = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }
        /// <summary>
        /// 对于java的 AES/CBC/NOPadding
        /// </summary>
        /// <param name="encryptStr"></param>
        /// <returns></returns>
        public string AESEncrypt_JavaNOPadding(string encryptStr)
        {
            byte[] keyArray = Encoding.UTF8.GetBytes(Key); ;
            byte[] toEncryptArray = Encoding.UTF8.GetBytes(encryptStr); 
            var aes = System.Security.Cryptography.Aes.Create();
            aes.IV = Encoding.UTF8.GetBytes(Key); ;
            aes.Key = keyArray;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.Zeros;
            ICryptoTransform cTransform = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }
        public string AESDEncrypt(string encryptStr)
        {
            byte[] keyArray = UTF8Encoding.UTF8.GetBytes(Key);
            byte[] toEncryptArray = Convert.FromBase64String(encryptStr);
            RijndaelManaged aes = new RijndaelManaged();
            aes.Key = keyArray;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            ICryptoTransform cTransform = aes.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            return UTF8Encoding.UTF8.GetString(resultArray);
        }
    }
}

