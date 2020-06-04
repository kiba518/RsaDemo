using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Utility;

namespace RsaDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            //DataCertificateHelper.CopyPfxAndGetInfo();
            //DataCertificateHelper.RsaTest();
            DataCertificateHelper.SubRsaTest();
            Console.ReadKey();
        }
    }
}
