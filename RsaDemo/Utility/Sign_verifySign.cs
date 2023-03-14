using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Utility
{
    /// <summary>
    /// RSA签名，可以和javaRSA签名交互
    /// </summary>
    public class Sign_verifySign
    {
        #region prepare string to sign.
        //example format: a=123&b=xxx&c (with sort)
        private static string encrypt<T>(T body)
        {
            var mType = body.GetType();
            var props = mType.GetProperties().OrderBy(x => x.Name).ToArray();
            StringBuilder sb = new StringBuilder();
            foreach (var p in props)
            {
                if (p.Name != "sign" && p.Name != "signType" && p.GetValue(body, null) != null && p.GetValue(body, null).ToString() != "")
                {
                    sb.Append(string.Format("{0}={1}&", p.Name, p.GetValue(body, null)));
                }
            }
            var tmp = sb.ToString();
            return tmp.Substring(0, tmp.Length - 1);
        }
        #endregion

        #region sign
        /// <summary>
        /// 对应JAVA的RSAwithSHA1
        /// </summary>
        /// <param name="content"></param>
        /// <param name="privateKey"></param>
        /// <param name="input_charset"></param>
        /// <returns></returns>
        public static string sign(string content, string privateKey, string input_charset="utf-8")
        {
            byte[] Data = Encoding.GetEncoding(input_charset).GetBytes(content);
            RSACryptoServiceProvider rsa = DecodePemPrivateKey(privateKey);
            SHA1 sh = new SHA1CryptoServiceProvider();
            byte[] signData = rsa.SignData(Data, sh);
            string base64Str = Convert.ToBase64String(signData);
            return base64Str;
            ////get base64string -> ASCII byte[]
            //var base64ToByte = Encoding.ASCII.GetBytes(Convert.ToBase64String(signData));
            //string signresult = BitConverter.ToString(base64ToByte).Replace("-", string.Empty);
            //return signresult;
        }
        private static RSACryptoServiceProvider DecodePemPrivateKey(String pemstr)
        {
            byte[] pkcs8privatekey; pkcs8privatekey = Convert.FromBase64String(pemstr);
            if (pkcs8privatekey != null)
            {
                RSACryptoServiceProvider rsa = DecodePrivateKeyInfo(pkcs8privatekey);
                return rsa;
            }
            else return null;
        }
        private static RSACryptoServiceProvider DecodePrivateKeyInfo(byte[] pkcs8)
        {
            byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15]; MemoryStream mem = new MemoryStream(pkcs8);
            int lenstream = (int)mem.Length; BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading            
            byte bt = 0;
            ushort twobytes = 0;
            try
            {
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130)    //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();    //advance 1 byte                
                else if (twobytes == 0x8230)
                    binr.ReadInt16();    //advance 2 bytes                
                else
                    return null;
                bt = binr.ReadByte();
                if (bt != 0x02)
                    return null;
                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0001)
                    return null;
                seq = binr.ReadBytes(15);        //read the Sequence OID                
                if (!CompareBytearrays(seq, SeqOID))    //make sure Sequence for OID is correct                   
                    return null;
                bt = binr.ReadByte();
                if (bt != 0x04)    //expect an Octet string                    
                    return null;
                bt = binr.ReadByte();        //read next byte, or next 2 bytes is  0x81 or 0x82; otherwise bt is the byte count 
                if (bt == 0x81)
                    binr.ReadByte();
                else
                if (bt == 0x82)
                    binr.ReadUInt16();                //------ at this stage, the remaining sequence should be the RSA private key                 
                byte[] rsaprivkey = binr.ReadBytes((int)(lenstream - mem.Position));
                RSACryptoServiceProvider rsacsp = DecodeRSAPrivateKey(rsaprivkey);
                return rsacsp;
            }
            catch (Exception)
            {
                return null;
            }
            finally
            {
                binr.Close();
            }
        }
        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int i = 0; foreach (byte c in a)
            { if (c != b[i]) return false; i++; }
            return true;
        }
        private static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
        {
            byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

            // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
            MemoryStream mem = new MemoryStream(privkey);
            BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;
            int elems = 0;
            try
            {
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();  //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();  //advance 2 bytes
                else
                    return null;

                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0102)  //version number
                    return null;
                bt = binr.ReadByte();
                if (bt != 0x00)
                    return null;


                //------  all private key components are Integer sequences ----
                elems = GetIntegerSize(binr);
                MODULUS = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                E = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                D = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                P = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                Q = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DP = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DQ = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                IQ = binr.ReadBytes(elems);

                // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSAParameters RSAparams = new RSAParameters();
                RSAparams.Modulus = MODULUS;
                RSAparams.Exponent = E;
                RSAparams.D = D;
                RSAparams.P = P;
                RSAparams.Q = Q;
                RSAparams.DP = DP;
                RSAparams.DQ = DQ;
                RSAparams.InverseQ = IQ;
                RSA.ImportParameters(RSAparams);
                return RSA;
            }
            catch (Exception e)
            {
                return null;
            }
            finally { binr.Close(); }
        }
        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)    //expect integer
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();  // data size in next byte
            else
                if (bt == 0x82)
            {
                highbyte = binr.ReadByte(); // data size in next 2 bytes
                lowbyte = binr.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;     // we already have the data size
            } while (binr.ReadByte() == 0x00)
            {  //remove high order zeros in data
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);    //last ReadByte wasn't a removed zero, so back up a byte
            return count;
        }

        #endregion

        #region verifySign
        //onepay verify
        public static bool verifyFromHexAscii(string sign, string publicKey, string content, string charset)
        {
            string decSign = System.Text.Encoding.UTF8.GetString(fromHexAscii(sign));
            return verify(content, decSign, publicKey, charset);
        }
        public static byte[] fromHexAscii(string s)
        {
            try
            {
                int len = s.Length;
                if ((len % 2) != 0)
                    throw new Exception("Hex ascii must be exactly two digits per byte.");

                int out_len = len / 2;
                byte[] out1 = new byte[out_len];
                int i = 0;
                StringReader sr = new StringReader(s);
                while (i < out_len)
                {
                    int val = (16 * fromHexDigit(sr.Read())) + fromHexDigit(sr.Read());
                    out1[i++] = (byte)val;
                }
                return out1;
            }
            catch (IOException e)
            {
                throw new Exception("IOException reading from StringReader?!?!");
            }
        }
        private static int fromHexDigit(int c)
        {
            if (c >= 0x30 && c < 0x3A)
                return c - 0x30;
            else if (c >= 0x41 && c < 0x47)
                return c - 0x37;
            else if (c >= 0x61 && c < 0x67)
                return c - 0x57;
            else
                throw new Exception('\'' + c + "' is not a valid hexadecimal digit.");
        }

        public static bool verify(string content, string signedString, string publicKey, string input_charset)
        {
            signedString = signedString.Replace("*", "+");
            signedString = signedString.Replace("-", "/");
            return JiJianverify(content, signedString, publicKey, input_charset);

        }
        public static bool JiJianverify(string content, string signedString, string publicKey, string input_charset)
        {
            bool result = false;
            byte[] Data = Encoding.GetEncoding(input_charset).GetBytes(content);

            byte[] data = Convert.FromBase64String(signedString);
            RSAParameters paraPub = ConvertFromPublicKey(publicKey);
            RSACryptoServiceProvider rsaPub = new RSACryptoServiceProvider();
            rsaPub.ImportParameters(paraPub);
            SHA1 sh = new SHA1CryptoServiceProvider();
            result = rsaPub.VerifyData(Data, sh, data);
            return result;
        }
        private static RSAParameters ConvertFromPublicKey(string pemFileConent)
        {

            byte[] keyData = Convert.FromBase64String(pemFileConent);
            if (keyData.Length < 162)
            {
                throw new ArgumentException("pem file content is incorrect.");
            }
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(keyData);

            RSAParameters para = new RSAParameters();
            para.Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned();
            para.Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned();
            return para;
        }
        #endregion
    }
}
