using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Utility;

namespace RsaDemo
{
    class Program
    {
        static String privateKey_NoXML = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKWgQbuMfuRULwZz8O8EDD1sadzFeaGtrDfLSwY3saF4mk+mXP8RkG2ty6seDlf5KoLQj2t1eYPp6ViCcXmuJcKPMmqZojMHWKMhEcWeizEfa+zfEE6YK+Yf2YgQMQWmP7uJ58vhln3n0tZzZk+IUoIyQUIkURKZ02iGi3X1gSi/AgMBAAECgYEAi5kljjR/B2hFMoUqf+rDfkoQeDohqLo/O8+nbpgmqdiDB7tLCtn9B9TCo3nz0QZ8ZEHxgDtFrn/LZASeLFcyDwzsPyWnJPrgs3tbYuRu0OsvcGZs28S4J+bN7GL7DFRnTU5J0aa5MsQC09VPo9r2Ljlsp2hy9Y208bYECuaiT2ECQQDa35zUFcD15HFbEKDet4HXpVtne5SCODoLUPoBahm/qGDp0id8s6eHSgx9wzq7Mg7uVoIpjBqx4J9UFBejLmTZAkEAwbhrWEZ2Otdjr8hesMjhS7j7WOnQtDq079j8UTz+M0QVM9rNjhxOte5si8wGtaqzbVFFMDGxisiWQnc3RKobVwJAXAkHg08acst6txZI7x4vJSTNSLh4fEF0dum4Fvwsk6EUD35lSFSrL4J9uixr9+dWy/Xoidv2JbIUjWBdiCqsEQJAK4yW7TBh8dZr/Z9w0hNGuqwqLRHbLjkoZecEygqJJuM+VPryTOlGNJYV5tOGCp8GWSP1BuGVBRsU1HpSfWg0XwJAJD9Dbccs0fjg48i/4s1R8FVgCaTKP5+1pweKVgeKBwuvucIlMvkjUlyjxMYuRjMoIbXHUP6Me21iCOo494/psA==";
        static String publicKey_NoXML = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCloEG7jH7kVC8Gc/DvBAw9bGncxXmhraw3y0sGN7GheJpPplz/EZBtrcurHg5X+SqC0I9rdXmD6elYgnF5riXCjzJqmaIzB1ijIRHFnosxH2vs3xBOmCvmH9mIEDEFpj+7iefL4ZZ959LWc2ZPiFKCMkFCJFESmdNohot19YEovwIDAQAB";
        static string appSecret = "e0f6d058e4184f4ab75831222c076b8c";
        static void Main(string[] args)
        {
            //DataCertificateHelper.CopyPfxAndGetInfo();
            //DataCertificateHelper.RsaTest();
            //DataCertificateHelper.SubRsaTest();
            //DataCertificateHelper.CopyPfxAndGetInfo();
            String testStr = "123"; 
            //string ret = Sign_verifySign.sign(testStr, privateKey_NoXML); 
            //string ret1 = GetSign(testStr, privateKey_NoXML); 
            AESUtil util = new AESUtil(appSecret.Substring(0, 16));
            string ret2 = util.AESEncrypt_JavaNOPadding("{\"cpOrderId\":\"1700065202303131128360106\",\"msg\":\"ok\",\"orderId\":\"1678678117981\",\"sendPropsRole\":\"1700065\",\"sendPropsTime\":\"2023-03-14 10:00:00\"}");
            Console.ReadKey();
        }
        #region RSA生成签名
        public static string GetSign(string fnstr, string privateKey)
        {
            //SHA256withRSA

            //1。转换私钥字符串为RSACryptoServiceProvider对象
            RSACryptoServiceProvider rsaP = RsaUtil.LoadPrivateKey(privateKey, "PKCS8");
            byte[] data = Encoding.UTF8.GetBytes(fnstr);//待签名字符串转成byte数组，UTF8
            byte[] byteSign = rsaP.SignData(data, "SHA1");//对应JAVA的RSAwithSHA256
            string sign = Convert.ToBase64String(byteSign);//签名byte数组转为BASE64字符串

            return sign;

        }
        #endregion
    }
}
