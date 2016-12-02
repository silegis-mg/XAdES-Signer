using Almg.Signer.XAdES.Interfaces;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.IO;

namespace Almg.Signer.XAdES
{
    /// <summary>
    /// Specifies the API that each platform specific XAdES signer should comply.
    /// This interface is required by the 'bait-and-switch" approach described in 
    /// https://blog.xamarin.com/creating-reusable-plugins-for-xamarin-forms/
    /// </summary>
	public interface IXAdESSigner  
	{
        /// <summary>
        /// Signs the supplied xml using the certificate and key provided.
        /// </summary>
        /// <param name="xml">XML that should be signed</param>
        /// <param name="signedXml">Stream that will receive the signed XML</param>
        /// <param name="signedElementXPath">XPath selector to the element that should be signed</param>
        /// <param name="certificate">Signer's certificate</param>
        /// <param name="key">Signer's private key</param>
        /// <returns>A signed enveloped XADES-BES XML</returns>
        void Sign(Stream xml, Stream signedXml, string signedElementXPath, X509Certificate certificate, AsymmetricKeyParameter key, PolicyIdentifier policyId);
	}
}