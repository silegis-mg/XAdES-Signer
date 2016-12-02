using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace System.Security.XmlCrypto
{
    public class HMACHelpers
    {
        public static byte[] ComputeMac(IMac mac, Stream s)
        {
            if (mac == null)
            {
                return null;
            }

            byte[] buffer = new byte[512];
            byte[] result = new byte[mac.GetMacSize()];
            int bytesRead;

            while ((bytesRead = s.Read(buffer, 0, buffer.Length)) > 0)
            {
                mac.BlockUpdate(buffer, 0, bytesRead);
            }

            mac.DoFinal(result, 0);
            return result;
        }
    }
}
