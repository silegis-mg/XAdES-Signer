using Almg.Signer.XAdES.Interfaces;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Linq;
using System.Security.XmlCrypto;
using System.Xml;

namespace System.Security.XmlCrypto.XAdES
{
    public class XAdESSignedXml : SignedXml
    {
        private const string SIGNED_PROPERTIES_NAMESPACE_URI = "http://uri.etsi.org/01903#SignedProperties";
        private const string XADES_NAMESPACE_URI = "http://uri.etsi.org/01903/v1.3.2#";
        private const string XML_DSIG_SHA256_NAMESPACE_URI = "http://www.w3.org/2001/04/xmlenc#sha256";

        private XmlDocument document;
        private XmlNamespaceManager xmlNamespaceManager;

        public X509Certificate Certificate { get; set; }
        public PolicyIdentifier PolicyId { get; set; }
        public string SignedElementXPath { get; set; }
        private SignedXml signedXML;

        public XAdESSignedXml(XmlDocument document) : this(document, new XmlNamespaceManager(document.NameTable))
        {

        }

        public XAdESSignedXml(XmlDocument document, XmlNamespaceManager namespaceManager): base(document, namespaceManager) {
            this.document = document;
            SignedElementXPath = "";

            namespaceManager.AddNamespace("xades", XADES_NAMESPACE_URI);
            namespaceManager.AddNamespace("ds", XmlDsigConstants.XmlDsigNamespaceUrl);
            xmlNamespaceManager = namespaceManager;
        }

        public void ComputeXAdESSignature()
        {
            this.KeyInfo = GetCertInfo(Certificate);
            this.AddReference(CreateRootReference(SignedElementXPath));

            var guid = Guid.NewGuid().ToString();
            this.Signature.Id = "signature-" + guid;
            this.Signature.SignatureValueId = "signature-value-" + guid;
            
            CreateXAdESObject();
            base.ComputeSignature();
        }      

        #region XML DSIG

        private KeyInfo GetCertInfo(X509Certificate cert)
        {
            KeyInfo keyInfo = new KeyInfo();

            KeyInfoX509Data keyInfoData = new KeyInfoX509Data(cert.GetEncoded());
            keyInfoData.AddIssuerSerial(cert.IssuerDN.ToString(), cert.SerialNumber.ToString());
            keyInfoData.AddSubjectName(cert.SubjectDN.ToString());
            keyInfo.AddClause(keyInfoData);
            return keyInfo;
        }

        private Reference CreateRootReference(string xpath)
        {
            Reference reference = new Reference();
            reference.Uri = xpath;
            reference.DigestMethod = XML_DSIG_SHA256_NAMESPACE_URI;

            //XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            //reference.AddTransform(env);

            //XmlDsigExcC14NTransform c14t = new XmlDsigExcC14NTransform();
            //reference.AddTransform(c14t);

            //defaults to Inclusive Canonicalization. TODO: Add API option to choose canonicalization method
            XmlDsigC14NTransform c14t = new XmlDsigC14NTransform();
            reference.AddTransform(c14t);

            return reference;
        }

        #endregion

        #region XAdES Nodes

        private void CreateXAdESObject()
        {
            var qualifyingPropertiesNode = CreateQualifyingPropertiesNode(this, document);
            var signedPropertiesNode = CreateSignedPropertiesNode(document, qualifyingPropertiesNode);

            var signedSignatureProperties = CreateSignedSignaturePropertiesNode(document, signedPropertiesNode);
            CreateSigningTimeNode(document, signedSignatureProperties);
            CreateSigningCertificateNode(document, signedSignatureProperties, Certificate);
            CreateSignaturePolicyIdentifier(document, signedSignatureProperties);

            var unsignedPropertiesNode = CreateUnsignedPropertiesNode(document, qualifyingPropertiesNode);
            CreateUnsignedSignaturePropertiesNode(document, unsignedPropertiesNode);

            DataObject dataObject = new DataObject();
            dataObject.Data = qualifyingPropertiesNode.SelectNodes(".");
            this.AddObject(dataObject);
        }

        private XmlElement CreateUnsignedPropertiesNode(XmlDocument document, XmlElement qualifyingPropertiesNode)
        {
            return CreateXMLNode(document, "UnsignedProperties", XADES_NAMESPACE_URI, qualifyingPropertiesNode);
        }

        private XmlElement CreateUnsignedSignaturePropertiesNode(XmlDocument document, XmlElement unsignedPropertiesNode)
        {
            return CreateXMLNode(document, "UnsignedSignatureProperties", XADES_NAMESPACE_URI, unsignedPropertiesNode);
        }

        private XmlElement CreateSignedSignaturePropertiesNode(XmlDocument document, XmlElement propertiesNode)
        {
            return CreateXMLNode(document, "SignedSignatureProperties", XADES_NAMESPACE_URI, propertiesNode);
        }

        private void CreateSigningTimeNode(XmlDocument document, XmlElement signedSignaturePropertiesNode)
        {
            CreateXMLNode(document, "SigningTime", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), XADES_NAMESPACE_URI, signedSignaturePropertiesNode);
        }

        private void CreateSigningCertificateNode(XmlDocument document, XmlElement signedSignatureProperties, X509Certificate certificate)
        {
            var signingCertificateNode = CreateXMLNode(document, "SigningCertificate", XADES_NAMESPACE_URI, signedSignatureProperties);
            var certNode = CreateXMLNode(document, "Cert", XADES_NAMESPACE_URI, signingCertificateNode);
            CreateCertDigestNode(document, certNode);
            CreateIssuerAndSerialNodes(document, certNode);
        }
        
        private void CreateIssuerAndSerialNodes(XmlDocument document, XmlElement certNode)
        {
            var issuerSerialNode = CreateXMLNode(document, "IssuerSerial", XADES_NAMESPACE_URI, certNode);

            //CertificateStructure.Issuer.ToString(true, X509Name.RFC2253Symbols)
            CreateXMLNode(document, "X509IssuerName", Certificate.CertificateStructure.Issuer.ToString(true, X509Name.RFC2253Symbols),
                                           XmlDsigConstants.XmlDsigNamespaceUrl, issuerSerialNode);
            CreateXMLNode(document, "X509SerialNumber", Certificate.SerialNumber.ToString(),
                                           XmlDsigConstants.XmlDsigNamespaceUrl, issuerSerialNode);
        }

        private void CreateCertDigestNode(XmlDocument document, XmlElement certNode)
        {
            var certDigestNode = CreateXMLNode(document, "CertDigest", XADES_NAMESPACE_URI, certNode);

            var digestMethod = CreateXMLNode(document, "DigestMethod", XmlDsigConstants.XmlDsigNamespaceUrl, certDigestNode);
            digestMethod.SetAttribute("Algorithm", XML_DSIG_SHA256_NAMESPACE_URI);

            var digestValue = GetBase64SHA256(Certificate.GetEncoded());
            CreateXMLNode(document, "DigestValue", digestValue, XmlDsigConstants.XmlDsigNamespaceUrl, certDigestNode);
        }

        private XmlElement CreateSignedPropertiesNode(XmlDocument document, XmlElement qualifyingPropertiesNode)
        {
            var signedPropertiesNode = CreateXMLNode(document, "SignedProperties", XADES_NAMESPACE_URI, qualifyingPropertiesNode);
            signedPropertiesNode.SetAttribute("Id", "signed-properties-" + Guid.NewGuid().ToString());

            var reference = new Reference("#" + signedPropertiesNode.GetAttribute("Id"));
            reference.Type = SIGNED_PROPERTIES_NAMESPACE_URI;
            reference.DigestMethod = XML_DSIG_SHA256_NAMESPACE_URI;

            //XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            //reference.AddTransform(env);

            XmlDsigExcC14NTransform c14t = new XmlDsigExcC14NTransform();
            reference.AddTransform(c14t);

            this.AddReference(reference);

            return signedPropertiesNode;
        }

        private XmlElement CreateQualifyingPropertiesNode(SignedXml signedXml, XmlDocument document)
        {       
            var result = document.CreateElement("QualifyingProperties", XADES_NAMESPACE_URI);
            result.Prefix = xmlNamespaceManager.LookupPrefix(XADES_NAMESPACE_URI);

            result.SetAttribute("Target", "#" + signedXml.Signature.Id);
            return result;
        }

        private void CreateSignaturePolicyIdentifier(XmlDocument document, XmlElement signedSignaturePropertiesNode)
        {
            if(PolicyId==null)
            {
                return;
            }

            XmlDocument policyXML = new XmlDocument();
            policyXML.Load(new MemoryStream(PolicyId.PolicyFile));
            XmlNamespaceManager ns = new XmlNamespaceManager(policyXML.NameTable);
            ns.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");
            var policyNode = policyXML.SelectSingleNode(@"//xades:Identifier", ns);

            var policyID = policyNode.InnerText;
            var policyQualifier = policyNode.Attributes["Qualifier"].Value;

            var hash = PolicyId.PolicyHash;
            if(hash==null)
            {
                //if a hash was not supplied, calculate the hash using the raw byte stream of the supplied policy
                hash = Convert.ToBase64String(XmlEncHashes.ComputeHash(XmlEncHashes.XmlDsigSHA256Url, PolicyId.PolicyFile));
            }

            var signaturePolicyIdentifier = CreateXMLNode(document, "SignaturePolicyIdentifier", XADES_NAMESPACE_URI, signedSignaturePropertiesNode);
            var signaturePolicyId = CreateXMLNode(document, "SignaturePolicyId", XADES_NAMESPACE_URI, signaturePolicyIdentifier);
            var sigPolicyId = CreateXMLNode(document, "SigPolicyId", XADES_NAMESPACE_URI, signaturePolicyId);

            var identifier = CreateXMLNode(document, "Identifier", XADES_NAMESPACE_URI, sigPolicyId);
            identifier.SetAttribute("Qualifier", policyQualifier);
            identifier.InnerText = policyID;

            var sigPolicyHash = CreateXMLNode(document, "SigPolicyHash", XADES_NAMESPACE_URI, signaturePolicyId);
            var digestMethod = CreateXMLNode(document, "DigestMethod", XmlDsigConstants.XmlDsigNamespaceUrl, sigPolicyHash);
            digestMethod.SetAttribute("Algorithm", XmlEncHashes.XmlDsigSHA256Url);
            
            CreateXMLNode(document, "DigestValue", hash, XmlDsigConstants.XmlDsigNamespaceUrl, sigPolicyHash);

            var sigPolicyQualifiers = CreateXMLNode(document, "SigPolicyQualifiers", XADES_NAMESPACE_URI, signaturePolicyId);
            var sigPolicyQualifier = CreateXMLNode(document, "SigPolicyQualifier", XADES_NAMESPACE_URI, sigPolicyQualifiers);
            CreateXMLNode(document, "SPURI", PolicyId.Url, XADES_NAMESPACE_URI, sigPolicyQualifier);
        }

        #endregion

        #region XML Helpers

        public XmlElement CreateXMLNode(XmlDocument document, string nodeName, string nameSpace, XmlElement rootNode)
        {
            string prefix = xmlNamespaceManager.LookupPrefix(nameSpace);

            XmlElement result;
            result = document.CreateElement(prefix, nodeName, nameSpace);
            rootNode.AppendChild(result);
            return result;
        }

        public XmlElement CreateXMLNode(XmlDocument document, string nodeName, string text, string nameSpace, XmlElement rootNode)
        {
            string prefix = xmlNamespaceManager.LookupPrefix(nameSpace);
            var newNode = CreateXMLNode(document, nodeName, nameSpace, rootNode);
            newNode.InnerText = text;
            newNode.Prefix = prefix;
            return newNode;
        }

        public override XmlElement GetIdElement(XmlDocument doc, string id)
        {
            if (String.IsNullOrEmpty(id))
                return null;

            var xmlElement = base.GetIdElement(doc, id);
            if (xmlElement != null)
                return xmlElement;
                        
            if (this.m_signature.ObjectList.Count == 0)
                return null;

            foreach (var dataObject in this.m_signature.ObjectList)
            {
                var nodeWithSameId = FindNodeByIdRecursive(((DataObject)dataObject).Data, id);
                if (nodeWithSameId != null)
                {
                    return nodeWithSameId;
                }
            }

            return null;
        }

        private XmlElement FindNodeByIdRecursive(XmlNodeList nodes, string value)
        {
            foreach (XmlNode node in nodes)
            {
                var attr = node.Attributes["Id"];
                if(attr!=null && attr.Value==value)
                {
                    return (XmlElement)node;
                } else
                {
                    return FindNodeByIdRecursive(node.ChildNodes, value);
                }
            }

            return null;
        }

        #endregion

        #region Crypto Helpers

        private static string GetBase64SHA256(byte[] inputBytes)
        {
            byte[] outputBytes = GetBytesSHA256(inputBytes);
            return Convert.ToBase64String(outputBytes);
        }

        private static byte[] GetBytesSHA256(byte[] inputBytes)
        {
            Sha256Digest sha256 = new Sha256Digest();
            return DigestHelper.ComputeHash(sha256, inputBytes);
        }

        #endregion
    }
}
