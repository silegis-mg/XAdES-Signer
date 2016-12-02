using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace System.Security.XmlCrypto
{
    public class DigestHelper
    {
        public static byte[] ComputeHash(IDigest digest, Stream s)
        {
            if (digest == null)
            {
                return null;
            }

            byte[] buffer = new byte[512];
            byte[] result = new byte[digest.GetDigestSize()];
            int bytesRead;

            while ((bytesRead = s.Read(buffer, 0, buffer.Length)) > 0)
            {
                digest.BlockUpdate(buffer, 0, bytesRead);
            }

            digest.DoFinal(result, 0);
            return result;
        }

        public static byte[] ComputeHash(IDigest digest, byte[] data)
        {
            if (digest == null)
            {
                return null;
            }


            byte[] result = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(result, 0);
            return result;
        }
    }
}
