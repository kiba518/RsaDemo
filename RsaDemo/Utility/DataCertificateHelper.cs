using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Diagnostics;
using Utility;
namespace Utility
{
    public static class DataCertificateHelper
    {
        private static readonly Encoding Encoder = Encoding.UTF8;
        //加密公钥
        public const string publicKey = "<RSAKeyValue><Modulus>18+I2j3HU/fXQasRXOWGegP3dG75I/It2n42rgeIATeftBkoQNH73Rz0IYW++arqd0Yy5hFpNkqzY/dOmD+bDXWUheWA0P/dVZf+qeWwVV+iW3lRAU8SmnPcaD35Ic1jMEPFQVeX1zGI2ofD8aGodeSRA4+JKo+KLgyGVGDI+d0=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        //解密私钥
        public const string privateKey = "<RSAKeyValue><Modulus>18+I2j3HU/fXQasRXOWGegP3dG75I/It2n42rgeIATeftBkoQNH73Rz0IYW++arqd0Yy5hFpNkqzY/dOmD+bDXWUheWA0P/dVZf+qeWwVV+iW3lRAU8SmnPcaD35Ic1jMEPFQVeX1zGI2ofD8aGodeSRA4+JKo+KLgyGVGDI+d0=</Modulus><Exponent>AQAB</Exponent><P>2EEAI+cO1fyvmGpg3ywMLHHZ1/X3ZrF6xZBNM2AL7bJFVfL8RS8UznUCdsL/R/o1b+lGo1CetlI++n6IvYYwyw==</P><Q>/3muAXWOU3SMKFWSDpHUgeM9kZev0ekQDefRSayXM8q9ItkaWTOJcIN614A0UGdYE6VX1ztPgveQFzm0qJDy9w==</Q><DP>NM/i/eGewOmd5IYONFJogq4nOlOKYNz1E6yC/gn1v83qmuvlaevuk+EFggVrHKPhSvxYUOgOao45bSlbsZVE8w==</DP><DQ>MKU7w91dh3iWw4tfr1SHUWAytglbGi41t2Af0taBSARftUX/pWKR1hHDD0vDKlgzRjJiooIRps966WE8jChliw==</DQ><InverseQ>YEIfQArVNP27AJn3WOBswHP/+gJ6Bk434MZ80CJONp4b6e+Ilxd2dwloxGKNbGgCyaNJEFI5J8qYSNNe0KqPkw==</InverseQ><D>ZAscSPesqLtS+WlBMkxgy719AGfVbRl+sjQiSwjIvq+3hDjJVUtCs90RO10SDBF0gfhz7f2SRY3ZnXTu5VtPF9KEQyUaY0F6eXwz4YQNzJTI2c1o5SFXZP8Ynqwltg8gNIhMe8bB6nVgASeADBim22DlSFCzmD3vt1gTI8nxmO0=</D></RSAKeyValue>";

        public static void CopyPfxAndGetInfo()
        {
            string keyName = "Kiba518.Licence";//证书的KEY
            var ret = DataCertificate.CreateCertWithPrivateKey(keyName, @"C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Bin\makecert.exe");
            if (ret)
            {
                DataCertificate.ExportToPfxFile(keyName, "Kiba518.pfx", "123456", true);
                X509Certificate2 x509 = DataCertificate.GetCertificateFromPfxFile("Kiba518.pfx", "123456");
                string publickey = x509.PublicKey.Key.ToXmlString(false);
                string privatekey = x509.PrivateKey.ToXmlString(true);
                Console.WriteLine($"公钥：{publickey}");
                Console.WriteLine($"私钥：{privatekey}");
                string myname = "my name is Kiba518!";
                string enStr = RSAEncrypt(publickey, myname);
             
                string deStr = RSADecrypt(privatekey, enStr);
               
            }
        }
        public static void RsaTest()
        {
            string myname = "my name is Kiba518!";
            Console.WriteLine($"内容：{myname}");
            string enStr = RSAEncrypt(publicKey, myname);
            Console.WriteLine($"加密字符串：{enStr}");
            string deStr = RSADecrypt(privateKey, enStr);
            Console.WriteLine($"解密字符串：{deStr}");
        }
        public static void SubRsaTest()
        {
            string myname = "my name is Kiba518!my name is Kiba518!my name is Kiba518!my name is Kiba518!my name is Kiba518!my name is Kiba518!my name is Kiba518!";
            Console.WriteLine($"内容：{myname}");
            string enStr = SubRSAEncrypt(publicKey, myname);
            Console.WriteLine($"加密字符串：{enStr}");
            string deStr = SubRSADecrypt(privateKey, enStr);
            Console.WriteLine($"解密字符串：{deStr}");
        }
        /// <summary> 
        /// RSA解密 
        /// </summary> 
        /// <param name="xmlPrivateKey"></param> 
        /// <param name="enptStr"></param> 
        /// <returns></returns> 
        public static string RSADecrypt(string xmlPrivateKey, string enptStr)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(xmlPrivateKey);
            byte[] rgb = Convert.FromBase64String(enptStr);
            byte[] bytes = provider.Decrypt(rgb, RSAEncryptionPadding.OaepSHA1);
            return new UnicodeEncoding().GetString(bytes);
        }
        /// <summary> 
        /// RSA加密 待加密的字节数不能超过密钥的长度值除以 8 再减去 11（即：RSACryptoServiceProvider.KeySize / 8 - 11），而加密后得到密文的字节数，正好是密钥的长度值除以 8（即：RSACryptoServiceProvider.KeySize / 8）。
        /// </summary> 
        /// <param name="xmlPublicKey"></param> 
        /// <param name="enptStr"></param> 
        /// <returns></returns> 
        public static string RSAEncrypt(string xmlPublicKey, string enptStr)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(xmlPublicKey);
            byte[] bytes = new UnicodeEncoding().GetBytes(enptStr);
            return Convert.ToBase64String(provider.Encrypt(bytes, RSAEncryptionPadding.OaepSHA1));
        }



        /// <summary>
        /// 分段加密，应对长字符串
        /// </summary>
        /// <param name="xmlPublicKey"></param>
        /// <param name="enptStr"></param>
        /// <returns></returns>
        public static String SubRSAEncrypt(string xmlPublicKey, string enptStr)
        { 
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(xmlPublicKey);
            Byte[] bytes = Encoder.GetBytes(enptStr);
            int MaxBlockSize = provider.KeySize / 8 - 11;    //加密块最大长度限制

            if (bytes.Length <= MaxBlockSize)
                return Convert.ToBase64String(provider.Encrypt(bytes, false));

            using (MemoryStream PlaiStream = new MemoryStream(bytes))
            using (MemoryStream CrypStream = new MemoryStream())
            {
                Byte[] Buffer = new Byte[MaxBlockSize];
                int BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);

                while (BlockSize > 0)
                {
                    Byte[] ToEncrypt = new Byte[BlockSize];
                    Array.Copy(Buffer, 0, ToEncrypt, 0, BlockSize);

                    Byte[] Cryptograph = provider.Encrypt(ToEncrypt, false);
                    CrypStream.Write(Cryptograph, 0, Cryptograph.Length);

                    BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);
                }

                return Convert.ToBase64String(CrypStream.ToArray(), Base64FormattingOptions.None);
            }

        }
        /// <summary>
        /// 分段解密，应对长字符串
        /// </summary>
        /// <param name="xmlPublicKey"></param>
        /// <param name="enptStr"></param>
        /// <returns></returns>
        public static String SubRSADecrypt(string xmlPublicKey, string enptStr)
        { 
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(xmlPublicKey);
            Byte[] bytes = Convert.FromBase64String(enptStr);
            int MaxBlockSize = provider.KeySize / 8;    //解密块最大长度限制

            if (bytes.Length <= MaxBlockSize)
                return Encoder.GetString(provider.Decrypt(bytes, false));

            using (MemoryStream CrypStream = new MemoryStream(bytes))
            using (MemoryStream PlaiStream = new MemoryStream())
            {
                Byte[] Buffer = new Byte[MaxBlockSize];
                int BlockSize = CrypStream.Read(Buffer, 0, MaxBlockSize);

                while (BlockSize > 0)
                {
                    Byte[] ToDecrypt = new Byte[BlockSize];
                    Array.Copy(Buffer, 0, ToDecrypt, 0, BlockSize);

                    Byte[] Plaintext = provider.Decrypt(ToDecrypt, false);
                    PlaiStream.Write(Plaintext, 0, Plaintext.Length);

                    BlockSize = CrypStream.Read(Buffer, 0, MaxBlockSize);
                }

                return Encoder.GetString(PlaiStream.ToArray());
            }
        }  
    }
}
