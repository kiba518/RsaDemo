using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RsaDemo.Utility
{
    public class JavaEncode
    {
        #region java endcode
        /// <summary>
        /// C# url编码跟java url编码后不一样，导致最后加密结果不一样
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        private string UrlEncode(string str)
        {
            var encoding = UTF8Encoding.UTF8;
            byte[] bytes = encoding.GetBytes(str);
            int IsSafe = 0;
            int NoSafe = 0;
            for (int i = 0; i < bytes.Length; i++)
            {
                char ch = (char)bytes[i];
                if (ch == ' ')
                {
                    IsSafe++;
                }
                else if (!IsSafeChar(ch))
                {
                    NoSafe++;
                }
            }
            if (IsSafe == 0 && NoSafe == 0)
            {
                return str;
            }
            byte[] buffer = new byte[bytes.Length + (NoSafe * 2)];
            int num1 = 0;
            for (int j = 0; j < bytes.Length; j++)
            {
                byte num2 = bytes[j];
                char ch2 = (char)num2;
                if (IsSafeChar(ch2))
                {
                    buffer[num1++] = num2;
                }
                else if (ch2 == ' ')
                {
                    buffer[num1++] = 0x2B;
                }
                else
                {
                    buffer[num1++] = 0x25;
                    buffer[num1++] = (byte)IntToHex((num2 >> 4) & 15);
                    buffer[num1++] = (byte)IntToHex(num2 & 15);
                }
            }
            return encoding.GetString(buffer);
        }

        private static bool IsSafeChar(char ch)
        {
            if ((((ch < 'a') || (ch > 'z')) && ((ch < 'A') || (ch > 'Z'))) && ((ch < '0') || (ch > '9')))
            {

                switch (ch)
                {
                    case '-':
                    case '.':
                        break;  //安全字符
                    case '+':
                    case ',':
                        return false;  //非安全字符
                    default:   //非安全字符
                        if (ch != '_')
                        {
                            return false;
                        }
                        break;
                }
            }
            return true;
        }
        private static char IntToHex(int n)
        {
            if (n <= 9)
            {
                return (char)(n + 0x30);
            }
            return (char)((n - 10) + 0x41);
        }
        #endregion
    }
}
