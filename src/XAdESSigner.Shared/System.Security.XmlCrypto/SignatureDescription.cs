using System;
using System.Collections.Generic;
using System.Text;

namespace System.Security.XmlCrypto
{
    public class SignatureDescription
    {
        public string HashName { get; }
        public string CipherName { get; }

        public SignatureDescription(string cipher, string hash)
        {
            this.HashName = hash;
            this.CipherName = cipher;
        }
    }
}
