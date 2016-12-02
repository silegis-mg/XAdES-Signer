using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace System.Security.XmlCrypto
{
    public class XmlEncHashes
    {
        private static Dictionary<string, string> hashes = new Dictionary<string, string>();

        public const string XmlDsigNamespaceUrl = "http://www.w3.org/2001/04/xmlenc#";
        public const string XmlDsigSHA1Url = XmlDsigNamespaceUrl + "sha1";
        public const string XmlDsigSHA256Url = XmlDsigNamespaceUrl + "sha256";
        public const string XmlDsigSHA512Url = XmlDsigNamespaceUrl + "sha512";
        public const string XmlDsigRIPEMD160Url = XmlDsigNamespaceUrl + "ripemd160";

        static XmlEncHashes()
        {
            hashes.Add(XmlDsigSHA1Url, "SHA_1");
            hashes.Add(XmlDsigSHA256Url, "SHA_256");
            hashes.Add(XmlDsigSHA512Url, "SHA_512");
            hashes.Add(XmlDsigRIPEMD160Url, "RIPEMD160");
        }

        public static byte[] ComputeHash(string hashUri, Stream s)
        {
            var digest = GetHashByUri(hashUri);
            return DigestHelper.ComputeHash(digest, s);
        }

        public static byte[] ComputeHash(string hashUri, byte[] data)
        {
            var digest = GetHashByUri(hashUri);
            return DigestHelper.ComputeHash(digest, data);
        }

        public static IDigest GetHashByUri(string hashUri)
        {
            return DigestUtilities.GetDigest(hashes[hashUri]); 
        }

        public static IDigest GetHashByName(string hashName)
        {
            return DigestUtilities.GetDigest(hashName);
        }
    }
}
