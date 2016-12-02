.NET XAdES Library
==================

This .NET library generates signed XML files that adheres to the XAdES standard on Windows, Xamarin Android and iOS.

This is still a work in progress. Right now only enveloped XAdES-BES signatures are supported.

Usage
-----

Just call the method Sign from a XAdESSigner instance providing an stream with the input XML, an output stream, a XPath selector to the element that should be signed, a Bouncycastle's X509Certificate instance and private AsymmetricKeyParameter instance.

This library can be called from PCL and Xamarin.Forms projects through the factory XAdESCrossPlatformSigner. 

```cs
IXAdESSigner xmlSigner = XAdESCrossPlatformSigner.Current;
xmlSigner.Sign(xmlStream, signedXmlStream, "#root", x509certificate, privateKey);
```

To-Do
-----

- Add support to signature policies (XAdES-EPES);
- Signature validation;
- Unit tests.