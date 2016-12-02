//
// RSAKeyValue.cs - RSAKeyValue implementation for XML Signature
//
// Author:
//	Sebastien Pouliot (spouliot@motus.com)
//
// (C) 2002, 2003 Motus Technologies Inc. (http://www.motus.com)
//

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

using Org.BouncyCastle.Crypto.Parameters;
using System.Text;
using System.Xml;

namespace System.Security.XmlCrypto {

	public class RSAKeyValue : KeyInfoClause {

		private RsaKeyParameters rsa;

		public RSAKeyValue () 
		{

		}

		public RSAKeyValue (RsaKeyParameters key) 
		{
			rsa = key;
		}

		public RsaKeyParameters Key {
			get { return rsa; }
			set { rsa = value; }
		}

		public override XmlElement GetXml () 
		{
			XmlDocument document = new XmlDocument ();
			XmlElement xel = document.CreateElement (XmlSignature.ElementNames.KeyValue, XmlSignature.NamespaceURI);
			xel.SetAttribute ("xmlns", XmlSignature.NamespaceURI);
			xel.InnerXml = ToXmlString (false);
			return xel;
		}

		public override void LoadXml (XmlElement value) 
		{
			if (value == null)
				throw new ArgumentNullException ();

			if ((value.LocalName != XmlSignature.ElementNames.KeyValue) || (value.NamespaceURI != XmlSignature.NamespaceURI))
				throw new CryptographicException ("value");
            //TODO
			//rsa.FromXmlString (value.InnerXml);
		}

        public string ToXmlString(bool includePrivateParameters)
        {
            StringBuilder sb = new StringBuilder();
            try
            {
                sb.Append("<RSAKeyValue>");

                sb.Append("<Modulus>");
                sb.Append(Convert.ToBase64String(rsa.Modulus.ToByteArray()));
                sb.Append("</Modulus>");

                sb.Append("<Exponent>");
                sb.Append(Convert.ToBase64String(rsa.Exponent.ToByteArray()));
                sb.Append("</Exponent>");

                if (includePrivateParameters && rsa is RsaPrivateCrtKeyParameters)
                {
                    var rsaPriv = (RsaPrivateCrtKeyParameters)rsa;
                    if (rsaPriv.P != null)
                    {
                        sb.Append("<P>");
                        sb.Append(Convert.ToBase64String(rsaPriv.P.ToByteArray()));
                        sb.Append("</P>");
                    }
                    if (rsaPriv.Q != null)
                    {
                        sb.Append("<Q>");
                        sb.Append(Convert.ToBase64String(rsaPriv.Q.ToByteArray()));
                        sb.Append("</Q>");
                    }
                    if (rsaPriv.DP != null)
                    {
                        sb.Append("<DP>");
                        sb.Append(Convert.ToBase64String(rsaPriv.DP.ToByteArray()));
                        sb.Append("</DP>");
                    }
                    if (rsaPriv.DQ != null)
                    {
                        sb.Append("<DQ>");
                        sb.Append(Convert.ToBase64String(rsaPriv.DQ.ToByteArray()));
                        sb.Append("</DQ>");
                    }
                    if (rsaPriv.QInv != null)
                    {
                        sb.Append("<InverseQ>");
                        sb.Append(Convert.ToBase64String(rsaPriv.QInv.ToByteArray()));
                        sb.Append("</InverseQ>");
                    }
                    sb.Append("<D>");
                    sb.Append(Convert.ToBase64String(rsaPriv.PublicExponent.ToByteArray()));
                    sb.Append("</D>");
                }

                sb.Append("</RSAKeyValue>");
            }
            catch
            {
                throw;
            }

            return sb.ToString();
        }
    }
}
