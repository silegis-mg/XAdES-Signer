XAdESSigner.Shared Project
==========================

This is a partial port of the System.Security.Cryptography.Xml assembly altered to use the BouncyCastle's cryptography 
primitives.

This code has dependencies on the XmlDocument class and cannot be a PCL project. That's why it is a shared project
imported by each native project.

In the future, we hope to remove the dependency on the old XmlDocument API and release a PCL version of this library.