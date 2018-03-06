using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Almg.Signer.XAdES.Interfaces
{
    public class PolicyIdentifier
    {
        public string Url { get; set; }
        public byte[] PolicyFile { get; set; }
        public string PolicyHash { get; set; }

        public PolicyIdentifier(string url, byte[] policyFile, string policyHash)
        {
            this.Url = url;
            this.PolicyFile = policyFile;
            this.PolicyHash = policyHash;
        }

        public PolicyIdentifier(string url, byte[] policyFile): this(url, policyFile, null)
        {
        }
    }
}
