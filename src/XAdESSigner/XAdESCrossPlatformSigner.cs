using System;

namespace Almg.Signer.XAdES
{
    /// <summary>
    /// This factory creates a IXAdESSigner instance for the current platform using the bait-and-switch approach
    /// </summary>
	public static class XAdESCrossPlatformSigner
	{
        static Lazy<IXAdESSigner> SIGNER = new Lazy<IXAdESSigner>(() => CreateSigner(), System.Threading.LazyThreadSafetyMode.PublicationOnly);

        public static IXAdESSigner Current
        {
            get
            {
                var ret = SIGNER.Value;
                if (ret == null)
                {
                    throw new NotImplementedException("This functionality is not implemented in the portable version of this assembly.  You should reference your Almg.Signer.XAdES NuGet package from your main application project in order to reference the platform-specific implementation.");
                }
                return ret;
            }
        }

        static IXAdESSigner CreateSigner()
        {
#if PORTABLE
            return null;
#else
            return new XAdESSigner();
#endif
        }
    }
}

