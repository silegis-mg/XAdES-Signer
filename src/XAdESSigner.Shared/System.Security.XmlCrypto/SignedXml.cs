//
// SignedXml.cs - SignedXml implementation for XML Signature
//
// Author:
//	Sebastien Pouliot  <sebastien@ximian.com>
//	Atsushi Enomoto <atsushi@ximian.com>
//      Tim Coleman <tim@timcoleman.com>
//
// (C) 2002, 2003 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) Tim Coleman, 2004
// Copyright (C) 2004-2005 Novell, Inc (http://www.novell.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System.Collections;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Policy;
using System.Net;
using System.Text;
using System.Xml;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace System.Security.XmlCrypto {

	public class SignedXml {

		protected Signature m_signature;
		private AsymmetricKeyParameter key;
		protected string m_strSigningKeyName;
		private XmlDocument envdoc;
		private XmlElement signatureElement;
		private Hashtable hashes;
		// FIXME: enable it after CAS implementation
		private XmlResolver xmlResolver = new XmlUrlResolver ();
		private ArrayList manifests;
        private XmlNamespaceManager namespaceManager;

        private static readonly char [] whitespaceChars = new char [] {' ', '\r', '\n', '\t'};

		public SignedXml (XmlNamespaceManager namespaceManager) 
		{
			m_signature = new Signature ();
			m_signature.SignedInfo = new SignedInfo ();
            this.namespaceManager = namespaceManager;
			hashes = new Hashtable (2); // 98% SHA1 for now
            DebugOutput = false;
		}

		public SignedXml (XmlDocument document, XmlNamespaceManager namespaceManager) : this (namespaceManager)
		{
			if (document == null)
				throw new ArgumentNullException ("document");
			envdoc = document;
		}

		public SignedXml (XmlElement elem, XmlNamespaceManager namespaceManager) : this(namespaceManager)
		{
			if (elem == null)
				throw new ArgumentNullException ("elem");
			envdoc = new XmlDocument ();
			envdoc.LoadXml (elem.OuterXml);
		}

		public KeyInfo KeyInfo {
			get {
				if (m_signature.KeyInfo == null)
					m_signature.KeyInfo = new KeyInfo ();
				return m_signature.KeyInfo;
			}
			set { m_signature.KeyInfo = value; }
		}

		public Signature Signature {
			get { return m_signature; }
		}

		public string SignatureLength {
			get { return m_signature.SignedInfo.SignatureLength; }
		}

		public string SignatureMethod {
			get { return m_signature.SignedInfo.SignatureMethod; }
		}

		public byte[] SignatureValue {
			get { return m_signature.SignatureValue; }
		}

		public SignedInfo SignedInfo {
			get { return m_signature.SignedInfo; }
		}

		public AsymmetricKeyParameter SigningKey {
			get { return key; }
			set { key = value; }
		}

		// NOTE: CryptoAPI related ? documented as fx internal
		public string SigningKeyName {
			get { return m_strSigningKeyName; }
			set { m_strSigningKeyName = value; }
		}

        public bool DebugOutput { get; set; }

        public string DebugOutputFolder { get; set; }

		public void AddObject (DataObject dataObject) 
		{
			m_signature.AddObject (dataObject);
		}

		public void AddReference (Reference reference) 
		{
			if (reference == null)
				throw new ArgumentNullException ("reference");
			m_signature.SignedInfo.AddReference (reference);
		}

		private Stream ApplyTransform (Transform t, XmlDocument input) 
		{
			// These transformer modify input document, which should
			// not affect to the input itself.
			if (t is XmlDsigXPathTransform 
				|| t is XmlDsigEnvelopedSignatureTransform
			)
				input = (XmlDocument) input.Clone ();

			t.LoadInput (input);

			if (t is XmlDsigEnvelopedSignatureTransform)
				// It returns XmlDocument for XmlDocument input.
				return CanonicalizeOutput (t.GetOutput ());

			object obj = t.GetOutput ();
			if (obj is Stream)
				return (Stream) obj;
			else if (obj is XmlDocument) {
				MemoryStream ms = new MemoryStream ();
				XmlTextWriter xtw = new XmlTextWriter (ms, Encoding.UTF8);
				((XmlDocument) obj).WriteTo (xtw);

				xtw.Flush ();

				// Rewind to the start of the stream
				ms.Position = 0;
				return ms;
			}
			else if (obj == null) {
				throw new NotImplementedException ("This should not occur. Transform is " + t + ".");
			}
			else {
				// e.g. XmlDsigXPathTransform returns XmlNodeList
				return CanonicalizeOutput (obj);
			}
		}

		private Stream CanonicalizeOutput (object obj)
		{
			Transform c14n = GetC14NMethod ();
			c14n.LoadInput (obj);
			return (Stream) c14n.GetOutput ();
		}

		private XmlDocument GetManifest (Reference r) 
		{
			XmlDocument doc = new XmlDocument ();
			doc.PreserveWhitespace = true;

			if (r.Uri [0] == '#') {
				// local manifest
				if (signatureElement != null) {
					XmlElement xel = GetIdElement (signatureElement.OwnerDocument, r.Uri.Substring (1));
					if (xel == null)
						throw new CryptographicException ("Manifest targeted by Reference was not found: " + r.Uri.Substring (1));
					doc.AppendChild (doc.ImportNode (xel, true));
					FixupNamespaceNodes (xel, doc.DocumentElement, false);
				}
			}
			else if (xmlResolver != null) {
				// TODO: need testing
				Stream s = (Stream) xmlResolver.GetEntity (new Uri (r.Uri), null, typeof (Stream));
				doc.Load (s);
			}

			if (doc.FirstChild != null) {
				// keep a copy of the manifests to check their references later
				if (manifests == null)
					manifests = new ArrayList ();
				manifests.Add (doc);

				return doc;
			}
			return null;
		}

		private void FixupNamespaceNodes (XmlElement src, XmlElement dst, bool ignoreDefault)
		{
			// add namespace nodes
			foreach (XmlAttribute attr in src.SelectNodes ("namespace::*")) {
				if (attr.LocalName == "xml")
					continue;
				if (ignoreDefault && attr.LocalName == "xmlns")
					continue;
				dst.SetAttributeNode (dst.OwnerDocument.ImportNode (attr, true) as XmlAttribute);
			}
		}

		private byte[] GetReferenceHash (Reference r, bool check_hmac) 
		{
			Stream s = null;
			XmlDocument doc = null;
			if (r.Uri == String.Empty) {
				doc = envdoc;
			}
			else if (r.Type == XmlSignature.Uri.Manifest) {
				doc = GetManifest (r);
			}
			else {
				doc = new XmlDocument ();
				doc.PreserveWhitespace = true;
				string objectName = null;

				if (r.Uri.StartsWith ("#xpointer")) {
					string uri = string.Join ("", r.Uri.Substring (9).Split (whitespaceChars));
					if (uri.Length < 2 || uri [0] != '(' || uri [uri.Length - 1] != ')')
						// FIXME: how to handle invalid xpointer?
						uri = String.Empty;
					else
						uri = uri.Substring (1, uri.Length - 2);
					if (uri == "/")
						doc = envdoc;
					else if (uri.Length > 6 && uri.StartsWith ("id(") && uri [uri.Length - 1] == ')')
						// id('foo'), id("foo")
						objectName = uri.Substring (4, uri.Length - 6);
				}
				else if (r.Uri [0] == '#') {
					objectName = r.Uri.Substring (1);
				}
				else if (xmlResolver != null) {
					// TODO: test but doc says that Resolver = null -> no access
					try {
						// no way to know if valid without throwing an exception
						Uri uri = new Uri (r.Uri);
						s = (Stream) xmlResolver.GetEntity (uri, null, typeof (Stream));
					}
					catch {
						// may still be a local file (and maybe not xml)
						s = File.OpenRead (r.Uri);
					}
				}
				if (objectName != null) {
					XmlElement found = null;
					foreach (DataObject obj in m_signature.ObjectList) {
						if (obj.Id == objectName) {
							found = obj.GetXml (this.namespaceManager);
							found.SetAttribute ("xmlns", XmlDsigConstants.XmlDsigNamespaceUrl);
							doc.AppendChild (doc.ImportNode (found, true));
							// FIXME: there should be theoretical justification of copying namespace declaration nodes this way.
							foreach (XmlNode n in found.ChildNodes)
								// Do not copy default namespace as it must be xmldsig namespace for "Object" element.
								if (n.NodeType == XmlNodeType.Element)
									FixupNamespaceNodes (n as XmlElement, doc.DocumentElement, true);
							break;
						}
					}
					if (found == null && envdoc != null) {
						found = GetIdElement (envdoc, objectName);
						if (found != null) {
							doc.AppendChild (doc.ImportNode (found, true));
							FixupNamespaceNodes(found, doc.DocumentElement, false);
                            //Copy root document namespaces to signedproperties
                            //FixupNamespaceNodes(envdoc.DocumentElement, doc.DocumentElement, false);
                        }
					}
					if (found == null)
						throw new CryptographicException (String.Format ("Malformed reference object: {0}", objectName));
				}
			}

			if (r.TransformChain.Count > 0) {		
				foreach (Transform t in r.TransformChain) {
					if (s == null) {
						s = ApplyTransform (t, doc);
					}
					else {
						t.LoadInput (s);
						object o = t.GetOutput ();
						if (o is Stream)
							s = (Stream) o;
						else
							s = CanonicalizeOutput (o);
					}
				}
			}
			else if (s == null) {
				// we must not C14N references from outside the document
				// e.g. non-xml documents
				if (r.Uri [0] != '#') {
					s = new MemoryStream ();
					doc.Save (s);
				}
				else {
                    // apply default C14N transformation
                    s = ApplyTransform(new XmlDsigC14NTransform(), doc);
                }
            }

            //Used to debug the output of the canonicalizer. We are having some problems related to 
            //different canonicalizer outputs between this implementation and Apache's santuario library.
            if(DebugOutput)
            {
                if(Directory.Exists(DebugOutputFolder))
                {
                    FileStream fs = new FileStream(Path.Combine(DebugOutputFolder, GetSafeFilename("ref" + r.Uri + ".xml")), FileMode.Create);
                    CopyStream(s, fs);
                    fs.Close();
                    s.Position = 0;
                }
            }

            return XmlEncHashes.ComputeHash(r.DigestMethod, s);
		}

        public string GetSafeFilename(string filename)
        {
            return string.Join("_", filename.Split(Path.GetInvalidFileNameChars()));
        }

        public static void CopyStream(Stream input, Stream output)
        {
            byte[] buffer = new byte[32768];
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, read);
            }
        }

        public static byte[] ReadFully(Stream input)
        {
            byte[] buffer = new byte[16 * 1024];
            using (MemoryStream ms = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }

        private void DigestReferences () 
		{
			// we must tell each reference which hash algorithm to use 
			// before asking for the SignedInfo XML !
			foreach (Reference r in m_signature.SignedInfo.References) {
				// assume SHA-1 if nothing is specified
				if (r.DigestMethod == null)
					r.DigestMethod = XmlDsigConstants.XmlDsigSHA1Url;
				r.DigestValue = GetReferenceHash (r, false);
			}
		}

		private Transform GetC14NMethod ()
		{
            Transform t = this.SignedInfo.CanonicalizationMethodObject;
            if(t==null)
            {
                throw new CryptographicException("Unknown Canonicalization Method {0}", m_signature.SignedInfo.CanonicalizationMethod);
            }				
			return t;
		}

		private Stream SignedInfoTransformed () 
		{
			Transform t = GetC14NMethod ();

			if (signatureElement == null) {
				// when creating signatures
				XmlDocument doc = new XmlDocument ();
				doc.PreserveWhitespace = true;
				doc.LoadXml (m_signature.SignedInfo.GetXml (this.namespaceManager).OuterXml);
				if (envdoc != null)
				foreach (XmlAttribute attr in envdoc.DocumentElement.SelectNodes ("namespace::*")) {
					if (attr.LocalName == "xml")
						continue;
					if (attr.Prefix == doc.DocumentElement.Prefix)
						continue;
					doc.DocumentElement.SetAttributeNode (doc.ImportNode (attr, true) as XmlAttribute);
				}
				t.LoadInput (doc);
			}
			else {
				// when verifying signatures
				// TODO - check m_signature.SignedInfo.Id
				XmlElement el = signatureElement.GetElementsByTagName (XmlSignature.ElementNames.SignedInfo, XmlSignature.NamespaceURI) [0] as XmlElement;
				StringWriter sw = new StringWriter ();
				XmlTextWriter xtw = new XmlTextWriter (sw);
				xtw.WriteStartElement (el.Prefix, el.LocalName, el.NamespaceURI);

				// context namespace nodes (except for "xmlns:xml")
				XmlNodeList nl = el.SelectNodes ("namespace::*");
				foreach (XmlAttribute attr in nl) {
					if (attr.ParentNode == el)
						continue;
					if (attr.LocalName == "xml")
						continue;
					if (attr.Prefix == el.Prefix)
						continue;
					attr.WriteTo (xtw);
				}
				foreach (XmlNode attr in el.Attributes)
					attr.WriteTo (xtw);
				foreach (XmlNode n in el.ChildNodes)
					n.WriteTo (xtw);

				xtw.WriteEndElement ();
				byte [] si = Encoding.UTF8.GetBytes (sw.ToString ());

				MemoryStream ms = new MemoryStream ();
				ms.Write (si, 0, si.Length);
				ms.Position = 0;

				t.LoadInput (ms);
			}
			// C14N and C14NWithComments always return a Stream in GetOutput
			return (Stream) t.GetOutput ();
		}

        /*
		public bool CheckSignature () 
		{
			return (CheckSignatureInternal (null) != null);
		}
        */
		private bool CheckReferenceIntegrity (ArrayList referenceList) 
		{
			if (referenceList == null)
				return false;

			// check digest (hash) for every reference
			foreach (Reference r in referenceList) {
				// stop at first broken reference
				byte[] hash = GetReferenceHash (r, true);
				if (! Compare (r.DigestValue, hash))
					return false;
			}
			return true;
		}

        /*
		public bool CheckSignature (AsymmetricAlgorithm key) 
		{
			if (key == null)
				throw new ArgumentNullException ("key");
			return (CheckSignatureInternal (key) != null);
		}

		private AsymmetricAlgorithm CheckSignatureInternal (AsymmetricAlgorithm key)
		{
			pkEnumerator = null;

			if (key != null) {
				// check with supplied key
				if (!CheckSignatureWithKey (key))
					return null;
			} else {
				if (Signature.KeyInfo == null)
					return null;
				// no supplied key, iterates all KeyInfo
				while ((key = GetPublicKey ()) != null) {
					if (CheckSignatureWithKey (key)) {
						break;
					}
				}
				pkEnumerator = null;
				if (key == null)
					return null;
			}

			// some parts may need to be downloaded
			// so where doing it last
			if (!CheckReferenceIntegrity (m_signature.SignedInfo.References))
				return null;

			if (manifests != null) {
				// do not use foreach as a manifest could contain manifests...
				for (int i=0; i < manifests.Count; i++) {
					Manifest manifest = new Manifest ((manifests [i] as XmlDocument).DocumentElement);
					if (! CheckReferenceIntegrity (manifest.References))
						return null;
				}
			}
			return key;
		}

		// Is the signature (over SignedInfo) valid ?
		private bool CheckSignatureWithKey (AsymmetricAlgorithm key) 
		{
			if (key == null)
				return false;

			SignatureDescription sd = (SignatureDescription) CryptoConfig.CreateFromName (m_signature.SignedInfo.SignatureMethod);
			if (sd == null)
				return false;

			AsymmetricSignatureDeformatter verifier = (AsymmetricSignatureDeformatter) CryptoConfig.CreateFromName (sd.DeformatterAlgorithm);
			if (verifier == null)
				return false;

			try {
				verifier.SetKey (key);
				verifier.SetHashAlgorithm (sd.DigestAlgorithm);

				HashAlgorithm hash = GetHash (sd.DigestAlgorithm, true);
				// get the hash of the C14N SignedInfo element
				MemoryStream ms = (MemoryStream) SignedInfoTransformed ();

				byte[] digest = hash.ComputeHash (ms);
				return verifier.VerifySignature (digest, m_signature.SignatureValue);
			}
			catch {
				// e.g. SignatureMethod != AsymmetricAlgorithm type
				return false;
			} 
		}
        */

		private bool Compare (byte[] expected, byte[] actual) 
		{
			bool result = ((expected != null) && (actual != null));
			if (result) {
				int l = expected.Length;
				result = (l == actual.Length);
				if (result) {
					for (int i=0; i < l; i++) {
						if (expected[i] != actual[i])
							return false;
					}
				}
			}
			return result;
		}

		public bool CheckSignature (IMac macAlg) 
		{
			if (macAlg == null)
				throw new ArgumentNullException ("macAlg");

			// Is the signature (over SignedInfo) valid ?
			Stream s = SignedInfoTransformed ();
			if (s == null)
				return false;

            byte[] actual = HMACHelpers.ComputeMac(macAlg, s);

            // HMAC signature may be partial and specified by <HMACOutputLength>
            if (m_signature.SignedInfo.SignatureLength != null) {
				int length = Int32.Parse (m_signature.SignedInfo.SignatureLength);
				// we only support signatures with a multiple of 8 bits
				// and the value must match the signature length
				if ((length & 7) != 0)
					throw new CryptographicException ("Signature length must be a multiple of 8 bits.");

				// SignatureLength is in bits (and we works on bytes, only in multiple of 8 bits)
				// and both values must match for a signature to be valid
				length >>= 3;
				if (length != m_signature.SignatureValue.Length)
					throw new CryptographicException ("Invalid signature length.");

				// is the length "big" enough to make the signature meaningful ? 
				// we use a minimum of 80 bits (10 bytes) or half the HMAC normal output length
				// e.g. HMACMD5 output 128 bits but our minimum is 80 bits (not 64 bits)
				int minimum = Math.Max (10, actual.Length / 2);
				if (length < minimum)
					throw new CryptographicException ("HMAC signature is too small");

				if (length < actual.Length) {
					byte[] trunked = new byte [length];
					Buffer.BlockCopy (actual, 0, trunked, 0, length);
					actual = trunked;
				}
			}

			if (Compare (m_signature.SignatureValue, actual)) {
				// some parts may need to be downloaded
				// so where doing it last
				return CheckReferenceIntegrity (m_signature.SignedInfo.References);
			}
			return false;
		}

		[ComVisible (false)]
		public bool CheckSignature (X509Certificate certificate, bool verifySignatureOnly)
		{
			throw new NotImplementedException ();
		}

		public void ComputeSignature () 
		{
			if (key != null) {

                if(m_signature.SignedInfo.SignatureMethod==null)
                {
                    //defaults do RSA SHA256 Signature
                    m_signature.SignedInfo.SignatureMethod = XmlDsigConstants.XmlDsigRSASHA256Url;
                }

                var sd = SignatureMethodParser.Parse(m_signature.SignedInfo.SignatureMethod);

                IDigest hash = XmlEncHashes.GetHashByName(sd.HashName);

                DigestReferences();

                ISigner signer = null;
				// in need for a CryptoConfig factory
				if (key is DsaKeyParameters)
                {
                    if (sd.CipherName!="DSA")
                    {
                        throw new CryptographicException("DSA SignatureAlgorithm is not supported by the signing key.");
                    }
                    signer = new DsaDigestSigner(new DsaSigner(), hash);
                } else if (key is RsaKeyParameters)
                {
                    if (sd.CipherName != "RSA")
                    {
                        throw new CryptographicException("RSA SignatureAlgorithm is not supported by the signing key.");
                    }
                    signer = new RsaDigestSigner(hash);
                }

				if (signer != null) {

                    signer.Init(true, key);

                    byte[] signed = SignerHelper.ComputeSignature(signer, SignedInfoTransformed());

					m_signature.SignatureValue = signed;
				}
			}
			else
				throw new CryptographicException ("signing key is not specified");
		}

		public void ComputeSignature (IMac macAlg) 
		{
			if (macAlg == null)
				throw new ArgumentNullException ("macAlg");

			string method = null;
            

            if (macAlg.AlgorithmName == MacUtilities.GetAlgorithmName(PkcsObjectIdentifiers.IdHmacWithSha1)) {
				method = XmlDsigConstants.XmlDsigHMACSHA1Url;
			} else if (macAlg.AlgorithmName == MacUtilities.GetAlgorithmName(PkcsObjectIdentifiers.IdHmacWithSha256)) {
				method = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
			} else if (macAlg.AlgorithmName == MacUtilities.GetAlgorithmName(PkcsObjectIdentifiers.IdHmacWithSha384)) {
				method = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384";
			} else if (macAlg.AlgorithmName == MacUtilities.GetAlgorithmName(PkcsObjectIdentifiers.IdHmacWithSha512)) {
				method = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";
			}
            /*
            TODO: RIPEMD160 support 
            else if (macAlg.AlgorithmName == MacUtilities.GetAlgorithmName(PkcsObjectIdentifiers.)) {
				method = "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160";
			} 
            */

            if (method == null)
				throw new CryptographicException ("unsupported algorithm");

			DigestReferences ();
			m_signature.SignedInfo.SignatureMethod = method;
			m_signature.SignatureValue = HMACHelpers.ComputeMac(macAlg, SignedInfoTransformed ());
		}

		public virtual XmlElement GetIdElement (XmlDocument document, string idValue) 
		{
			if ((document == null) || (idValue == null))
				return null;

			// this works only if there's a DTD or XSD available to define the ID
			XmlElement xel = document.GetElementById (idValue);
			if (xel == null) {
				// search an "undefined" ID
				xel = (XmlElement) document.SelectSingleNode ("//*[@Id='" + idValue + "']");
				if (xel == null) {
					xel = (XmlElement) document.SelectSingleNode ("//*[@ID='" + idValue + "']");
					if (xel == null) {
						xel = (XmlElement) document.SelectSingleNode ("//*[@id='" + idValue + "']");
					}
				}
			}
			return xel;
		}
        
		public XmlElement GetXml () 
		{
			return m_signature.GetXml (envdoc);
		}

		public void LoadXml (XmlElement value) 
		{
			if (value == null)
				throw new ArgumentNullException ("value");

			signatureElement = value;
			m_signature.LoadXml (value);
		}

		[ComVisible (false)]
		public XmlResolver Resolver {
			set { xmlResolver = value; }
		}
	}
}
