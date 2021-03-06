//
// KeyInfoNode.cs - KeyInfoNode implementation for XML Signature
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

using System.Xml;

namespace System.Security.XmlCrypto {

	public class KeyInfoNode : KeyInfoClause {

		private XmlElement Node;

		public KeyInfoNode () {}

		public KeyInfoNode (XmlElement node) 
		{
			LoadXml (node);
		}

		public XmlElement Value {
			get { return Node; }
			set { Node = value; }
		}

		public override XmlElement GetXml (XmlNamespaceManager xmlNamespaceManager) 
		{
			return Node;
		}

		// LAMESPEC: No ArgumentNullException is thrown if value == null
		public override void LoadXml (XmlElement value) 
		{
			Node = value;
		}
	}
}