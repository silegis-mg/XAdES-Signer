using System;
using System.Collections.Generic;
using System.Text;

namespace System.Security.XmlCrypto
{
    public class CryptographicException: Exception
    {
        public CryptographicException(): base()
        {

        }

        public CryptographicException(string msg): base(msg)
        {

        }

        public CryptographicException(string message, Exception innerException): base(message, innerException)
        {

        }

        public CryptographicException(String format, params object[] args): base(string.Format(format, args))
        {

        }
    }
}
