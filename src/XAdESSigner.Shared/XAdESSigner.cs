using Almg.Signer.XAdES;
using Almg.Signer.XAdES.Interfaces;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.XmlCrypto.XAdES;
using System.Text;
using System.Xml;

namespace Almg.Signer.XAdES
{
    public class XAdESSigner : IXAdESSigner
    {
        public XAdESSigner()
        {

        }

        public void Sign(Stream xml, Stream signature, string signedElementXPath, X509Certificate certificate, AsymmetricKeyParameter key, PolicyIdentifier policyId)
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.Load(xml);

            XAdESSignedXml signedXML = new XAdESSignedXml(xmlDoc);
            signedXML.SigningKey = key;
            
            signedXML.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            signedXML.Certificate = certificate;
            signedXML.SignedElementXPath = signedElementXPath;
            signedXML.PolicyId = policyId;
            signedXML.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";

            signedXML.ComputeXAdESSignature();

            XmlElement xmlDigitalSignature = signedXML.GetXml();

            //xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
            
            XmlTextWriter wr = new XmlTextWriter(signature, Encoding.UTF8);
            wr.Formatting = Formatting.None;
            xmlDigitalSignature.WriteTo(wr);
            wr.Flush();
            signature.Position = 0;
        }
    }
}
