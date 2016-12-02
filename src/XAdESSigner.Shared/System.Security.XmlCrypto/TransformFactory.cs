using System;
using System.Collections.Generic;
using System.Security.XmlCrypto;
using System.Text;

namespace XAdESSigner.Shared.System.Security.XmlCrypto
{
    public class TransformFactory
    {
        public static Transform fromURI(string uri)
        {
            Transform t = null;
            switch (uri)
            {
                case "http://www.w3.org/TR/2001/REC-xml-c14n-20010315":
                    t = new XmlDsigC14NTransform();
                    break;
                case "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments":
                    t = new XmlDsigC14NWithCommentsTransform();
                    break;
                case "http://www.w3.org/2000/09/xmldsig#enveloped-signature":
                    t = new XmlDsigEnvelopedSignatureTransform();
                    break;
                case "http://www.w3.org/TR/1999/REC-xpath-19991116":
                    t = new XmlDsigXPathTransform();
                    break;
                case "http://www.w3.org/TR/1999/REC-xslt-19991116":
                    t = new XmlDsigXsltTransform();
                    break;
                case "http://www.w3.org/2001/10/xml-exc-c14n#":
                    t = new XmlDsigExcC14NTransform();
                    break;
            }
            return t;
        }

    }
}
