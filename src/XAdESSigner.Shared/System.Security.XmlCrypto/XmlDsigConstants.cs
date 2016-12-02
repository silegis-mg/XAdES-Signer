using System;
using System.Collections.Generic;
using System.Text;

namespace System.Security.XmlCrypto
{
    /**
     * Constants related to the XML-DSIG standard (https://www.w3.org/TR/xmlsec-algorithms/)
     */
    public class XmlDsigConstants
    {
        public const string XmlDsigCanonicalizationUrl = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        public const string XmlDsigCanonicalizationWithCommentsUrl = XmlDsigCanonicalizationUrl + "#WithComments";
        public const string XmlDsigDSAUrl = XmlDsigNamespaceUrl + "dsa-sha1";
        public const string XmlDsigHMACSHA1Url = XmlDsigNamespaceUrl + "hmac-sha1";
        public const string XmlDsigMinimalCanonicalizationUrl = XmlDsigNamespaceUrl + "minimal";

        public const string XmlDsigNamespaceUrl = "http://www.w3.org/2000/09/xmldsig#";
        public const string XmlDsigMoreNamespaceUrl = "http://www.w3.org/2001/04/xmldsig-more#";

        public const string XmlDsigRSASHA1Url = XmlDsigNamespaceUrl + "rsa-sha1";
        public const string XmlDsigRSASHA256Url = XmlDsigMoreNamespaceUrl + "rsa-sha256";
        public const string XmlDsigRSASHA384Url = XmlDsigMoreNamespaceUrl + "rsa-sha384";
        public const string XmlDsigRSASHA512Url = XmlDsigMoreNamespaceUrl + "rsa-sha512";

        public const string XmlDsigSHA1Url = XmlDsigNamespaceUrl + "sha1";

        public const string XmlDecryptionTransformUrl = "http://www.w3.org/2002/07/decrypt#XML";
        public const string XmlDsigBase64TransformUrl = XmlDsigNamespaceUrl + "base64";
        public const string XmlDsigC14NTransformUrl = XmlDsigCanonicalizationUrl;
        public const string XmlDsigC14NWithCommentsTransformUrl = XmlDsigCanonicalizationWithCommentsUrl;
        public const string XmlDsigEnvelopedSignatureTransformUrl = XmlDsigNamespaceUrl + "enveloped-signature";
        public const string XmlDsigExcC14NTransformUrl = "http://www.w3.org/2001/10/xml-exc-c14n#";
        public const string XmlDsigExcC14NWithCommentsTransformUrl = XmlDsigExcC14NTransformUrl + "WithComments";
        public const string XmlDsigXPathTransformUrl = "http://www.w3.org/TR/1999/REC-xpath-19991116";
        public const string XmlDsigXsltTransformUrl = "http://www.w3.org/TR/1999/REC-xslt-19991116";
    }
}
