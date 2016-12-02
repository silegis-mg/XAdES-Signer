using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace System.Security.XmlCrypto
{
    public class SignerHelper
    {
        public static byte[] ComputeSignature(ISigner signer, Stream s)
        {
            if (signer == null)
            {
                return null;
            }

            byte[] buffer = new byte[512];
            int bytesRead;

            while ((bytesRead = s.Read(buffer, 0, buffer.Length)) > 0)
            {
                signer.BlockUpdate(buffer, 0, bytesRead);
            }

            return signer.GenerateSignature();
        }
    }
}
