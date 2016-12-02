using System;
using System.Collections.Generic;
using System.Text;

namespace System.Security.XmlCrypto
{
    public class SignatureMethodParser
    {
        public static SignatureDescription Parse(string uri)
        {
            switch(uri)
            {
                case XmlDsigConstants.XmlDsigRSASHA1Url:
                    return new SignatureDescription("RSA", "SHA_1");
                case XmlDsigConstants.XmlDsigRSASHA256Url:
                    return new SignatureDescription("RSA", "SHA_256");
                case XmlDsigConstants.XmlDsigRSASHA384Url:
                    return new SignatureDescription("RSA", "SHA_384");
                case XmlDsigConstants.XmlDsigRSASHA512Url:
                    return new SignatureDescription("RSA", "SHA_512");
                default: 
                    throw new CryptographicException("SignatureMethod not supported");
            }
        }
    }
}
