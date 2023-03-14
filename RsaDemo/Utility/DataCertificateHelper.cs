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

       

        #region RSA使用无XML公钥生成RSACryptoServiceProvider，然后验证签名签名，java提供，未测试
        /// <summary>
        /// 通过公钥生成RSACryptoServiceProvider
        /// </summary>
        /// <param name="x509key"></param>
        /// <returns></returns>
        private static RSACryptoServiceProvider DecodeX509PublicKey(byte[] x509key)
        {
            byte[] SeqOID = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

            MemoryStream ms = new MemoryStream(x509key);
            BinaryReader reader = new BinaryReader(ms);

            if (reader.ReadByte() == 0x30)
                ReadASNLength(reader); //skip the size
            else
                return null;

            int identifierSize = 0; //total length of Object Identifier section
            if (reader.ReadByte() == 0x30)
                identifierSize = ReadASNLength(reader);
            else
                return null;

            if (reader.ReadByte() == 0x06) //is the next element an object identifier?
            {
                int oidLength = ReadASNLength(reader);
                byte[] oidBytes = new byte[oidLength];
                reader.Read(oidBytes, 0, oidBytes.Length);

                if (oidBytes.SequenceEqual(SeqOID) == false) //is the object identifier rsaEncryption PKCS#1?
                    return null;

                int remainingBytes = identifierSize - 2 - oidBytes.Length;
                reader.ReadBytes(remainingBytes);
            }

            if (reader.ReadByte() == 0x03) //is the next element a bit string?
            {
                ReadASNLength(reader); //skip the size
                reader.ReadByte(); //skip unused bits indicator
                if (reader.ReadByte() == 0x30)
                {
                    ReadASNLength(reader); //skip the size
                    if (reader.ReadByte() == 0x02) //is it an integer?
                    {
                        int modulusSize = ReadASNLength(reader);
                        byte[] modulus = new byte[modulusSize];
                        reader.Read(modulus, 0, modulus.Length);
                        if (modulus[0] == 0x00) //strip off the first byte if it's 0
                        {
                            byte[] tempModulus = new byte[modulus.Length - 1];
                            Array.Copy(modulus, 1, tempModulus, 0, modulus.Length - 1);
                            modulus = tempModulus;
                        }

                        if (reader.ReadByte() == 0x02) //is it an integer?
                        {
                            int exponentSize = ReadASNLength(reader);
                            byte[] exponent = new byte[exponentSize];
                            reader.Read(exponent, 0, exponent.Length);

                            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                            RSAParameters RSAKeyInfo = new RSAParameters();
                            RSAKeyInfo.Modulus = modulus;
                            RSAKeyInfo.Exponent = exponent;
                            RSA.ImportParameters(RSAKeyInfo);
                            return RSA;
                        }
                    }
                }
            }
            return null;
        }
        
        private static int ReadASNLength(BinaryReader reader)
        {
            //Note: this method only reads lengths up to 4 bytes long as
            //this is satisfactory for the majority of situations.
            int length = reader.ReadByte();
            if ((length & 0x00000080) == 0x00000080) //is the length greater than 1 byte
            {
                int count = length & 0x0000000f;
                byte[] lengthBytes = new byte[4];
                reader.Read(lengthBytes, 4 - count, count);
                Array.Reverse(lengthBytes); //
                length = BitConverter.ToInt32(lengthBytes, 0);
            }
            return length;
        }

        static String privateKey_NoXML = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKWgQbuMfuRULwZz8O8EDD1sadzFeaGtrDfLSwY3saF4mk+mXP8RkG2ty6seDlf5KoLQj2t1eYPp6ViCcXmuJcKPMmqZojMHWKMhEcWeizEfa+zfEE6YK+Yf2YgQMQWmP7uJ58vhln3n0tZzZk+IUoIyQUIkURKZ02iGi3X1gSi/AgMBAAECgYEAi5kljjR/B2hFMoUqf+rDfkoQeDohqLo/O8+nbpgmqdiDB7tLCtn9B9TCo3nz0QZ8ZEHxgDtFrn/LZASeLFcyDwzsPyWnJPrgs3tbYuRu0OsvcGZs28S4J+bN7GL7DFRnTU5J0aa5MsQC09VPo9r2Ljlsp2hy9Y208bYECuaiT2ECQQDa35zUFcD15HFbEKDet4HXpVtne5SCODoLUPoBahm/qGDp0id8s6eHSgx9wzq7Mg7uVoIpjBqx4J9UFBejLmTZAkEAwbhrWEZ2Otdjr8hesMjhS7j7WOnQtDq079j8UTz+M0QVM9rNjhxOte5si8wGtaqzbVFFMDGxisiWQnc3RKobVwJAXAkHg08acst6txZI7x4vJSTNSLh4fEF0dum4Fvwsk6EUD35lSFSrL4J9uixr9+dWy/Xoidv2JbIUjWBdiCqsEQJAK4yW7TBh8dZr/Z9w0hNGuqwqLRHbLjkoZecEygqJJuM+VPryTOlGNJYV5tOGCp8GWSP1BuGVBRsU1HpSfWg0XwJAJD9Dbccs0fjg48i/4s1R8FVgCaTKP5+1pweKVgeKBwuvucIlMvkjUlyjxMYuRjMoIbXHUP6Me21iCOo494/psA==";
        static String publicKey_NoXML = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCloEG7jH7kVC8Gc/DvBAw9bGncxXmhraw3y0sGN7GheJpPplz/EZBtrcurHg5X+SqC0I9rdXmD6elYgnF5riXCjzJqmaIzB1ijIRHFnosxH2vs3xBOmCvmH9mIEDEFpj+7iefL4ZZ959LWc2ZPiFKCMkFCJFESmdNohot19YEovwIDAQAB";

        public static bool VerifySignature(string sign1, string sign2)
        {
            Byte[] byPkey = Convert.FromBase64String(publicKey_NoXML);
            RSACryptoServiceProvider rsacp = DecodeX509PublicKey(byPkey); 
            byte[] verify = Encoding.UTF8.GetBytes(sign1);
            byte[] signature = Convert.FromBase64String(sign2);
            bool ok = rsacp.VerifyData(verify, "SHA1", signature);
            return ok;

        }

        //public static string Signature(string fnstr)
        //{ 
        //    RSACryptoServiceProvider rsacp = DecodeRSAPrivateKey(privateKey_NoXML);
        //    byte[] data = Encoding.UTF8.GetBytes(fnstr);//待签名字符串转成byte数组，UTF8
        //    byte[] byteSign = rsacp.SignData(data, "SHA1");//对应JAVA的RSAwithSHA256
        //    string sign = Convert.ToBase64String(byteSign);//签名byte数组转为BASE64字符串

        //    return sign; 

        //}
        #endregion
    }
}
